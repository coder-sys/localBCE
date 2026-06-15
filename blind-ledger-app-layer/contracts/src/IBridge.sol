// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBridge {
    function triggerPayment(bytes32 claimId, address recipient, uint256 amount) external returns (bytes32 settlementRef);
}

contract CircleBridgeStub is IBridge {
    event CirclePaymentStub(bytes32 indexed claimId, address indexed recipient, uint256 amount, bytes32 settlementRef);

    function triggerPayment(bytes32 claimId, address recipient, uint256 amount) external returns (bytes32 settlementRef) {
        settlementRef = keccak256(abi.encodePacked("CIRCLE_BRIDGE_STUB", claimId, recipient, amount));
        emit CirclePaymentStub(claimId, recipient, amount, settlementRef);
    }
}

contract FedNowBridgeStub is IBridge {
    event FedNowPaymentStub(bytes32 indexed claimId, address indexed recipient, uint256 amount, bytes32 settlementRef);

    function triggerPayment(bytes32 claimId, address recipient, uint256 amount) external returns (bytes32 settlementRef) {
        settlementRef = keccak256(abi.encodePacked("FEDNOW_BRIDGE_STUB", claimId, recipient, amount));
        emit FedNowPaymentStub(claimId, recipient, amount, settlementRef);
    }
}

