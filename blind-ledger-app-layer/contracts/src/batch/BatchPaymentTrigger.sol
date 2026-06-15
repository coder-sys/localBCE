// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BatchClaimsRegistry.sol";

interface ISettlementBridge {
    function submitProviderPayment(
        bytes32 batchId,
        address recipient,
        bytes32 paymentRecord
    ) external returns (bytes32 settlementRef);
}

contract CPNAdapterStub is ISettlementBridge {
    string public constant STATUS = "CPN MANAGED PAYMENTS STUB / NO REAL MONEY MOVEMENT";

    event ProviderPaymentPrepared(bytes32 indexed batchId, address indexed recipient, bytes32 indexed paymentRecord, bytes32 settlementRef);

    function submitProviderPayment(
        bytes32 batchId,
        address recipient,
        bytes32 paymentRecord
    ) external returns (bytes32 settlementRef) {
        settlementRef = keccak256(abi.encodePacked("CPN_MANAGED_PAYMENTS_STUB", batchId, recipient, paymentRecord));
        emit ProviderPaymentPrepared(batchId, recipient, paymentRecord, settlementRef);
    }
}

contract BatchPaymentTrigger {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    ISettlementBridge public bridge;
    BatchClaimsRegistry public registry;
    uint256 public adminCount;
    mapping(bytes32 => mapping(address => bool)) internal roles;
    mapping(bytes32 => mapping(bytes32 => bool)) public paymentSubmitted;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event ProviderPaymentSubmitted(bytes32 indexed batchId, address indexed recipient, bytes32 indexed paymentRecord, bytes32 settlementRef);
    event BatchPaymentSubmitted(bytes32 indexed batchId, uint256 includedProviderCount);

    constructor(address initialAdmin, ISettlementBridge _bridge, BatchClaimsRegistry _registry) {
        require(initialAdmin != address(0), "admin zero");
        require(address(_bridge) != address(0), "bridge zero");
        require(address(_registry) != address(0), "registry zero");
        roles[ADMIN_ROLE][initialAdmin] = true;
        roles[OPERATOR_ROLE][initialAdmin] = true;
        adminCount = 1;
        bridge = _bridge;
        registry = _registry;
        emit RoleGranted(ADMIN_ROLE, initialAdmin);
        emit RoleGranted(OPERATOR_ROLE, initialAdmin);
    }

    modifier onlyAdmin() {
        require(roles[ADMIN_ROLE][msg.sender], "not admin");
        _;
    }

    modifier onlyBatchSubmitter() {
        require(roles[ADMIN_ROLE][msg.sender] || roles[OPERATOR_ROLE][msg.sender], "not authorized");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyAdmin {
        require(role == ADMIN_ROLE || role == OPERATOR_ROLE, "unknown role");
        require(account != address(0), "account zero");
        if (role == ADMIN_ROLE && !roles[ADMIN_ROLE][account]) {
            adminCount += 1;
        }
        roles[role][account] = true;
        emit RoleGranted(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyAdmin {
        require(role == ADMIN_ROLE || role == OPERATOR_ROLE, "unknown role");
        if (role == ADMIN_ROLE && roles[ADMIN_ROLE][account]) {
            require(adminCount > 1, "last admin");
            adminCount -= 1;
        }
        roles[role][account] = false;
        emit RoleRevoked(role, account);
    }

    function submitBatchForPayment(
        bytes32 batchId,
        address[] calldata recipients,
        bytes32[] calldata paymentRecords,
        bytes32[][] calldata paymentRecordPaths,
        uint256[] calldata paymentRecordIndexes
    ) external onlyBatchSubmitter returns (bytes32[] memory settlementRefs) {
        require(
            recipients.length == paymentRecords.length
                && recipients.length == paymentRecordPaths.length
                && recipients.length == paymentRecordIndexes.length,
            "length mismatch"
        );
        settlementRefs = new bytes32[](recipients.length);
        uint256 included;
        for (uint256 i = 0; i < recipients.length; i++) {
            bytes32 payeeRecord = sha256(abi.encodePacked(recipients[i], paymentRecords[i]));
            require(registry.checkPaymentInBatch(batchId, payeeRecord, paymentRecordPaths[i], paymentRecordIndexes[i]), "payment not in batch");
            require(!paymentSubmitted[batchId][payeeRecord], "payment already submitted");
            paymentSubmitted[batchId][payeeRecord] = true;
            settlementRefs[i] = bridge.submitProviderPayment(batchId, recipients[i], paymentRecords[i]);
            included++;
            emit ProviderPaymentSubmitted(batchId, recipients[i], payeeRecord, settlementRefs[i]);
        }
        emit BatchPaymentSubmitted(batchId, included);
    }

    function triggerBatchSettlement(
        bytes32 batchId,
        bytes32 paymentRecord,
        bytes32[] calldata paymentRecordPath,
        uint256 paymentRecordIndex
    ) external onlyBatchSubmitter returns (bytes32 settlementRef) {
        bytes32 payeeRecord = sha256(abi.encodePacked(address(this), paymentRecord));
        require(registry.checkPaymentInBatch(batchId, payeeRecord, paymentRecordPath, paymentRecordIndex), "payment not in batch");
        require(!paymentSubmitted[batchId][payeeRecord], "payment already submitted");
        paymentSubmitted[batchId][payeeRecord] = true;
        settlementRef = bridge.submitProviderPayment(batchId, address(this), paymentRecord);
        emit ProviderPaymentSubmitted(batchId, address(this), payeeRecord, settlementRef);
    }

    function triggerProviderNetSettlement(
        bytes32 batchId,
        address recipient,
        bytes32 paymentRecord,
        bytes32[] calldata paymentRecordPath,
        uint256 paymentRecordIndex
    ) external onlyBatchSubmitter returns (bytes32 settlementRef) {
        bytes32 payeeRecord = sha256(abi.encodePacked(recipient, paymentRecord));
        require(registry.checkPaymentInBatch(batchId, payeeRecord, paymentRecordPath, paymentRecordIndex), "payment not in batch");
        require(!paymentSubmitted[batchId][payeeRecord], "payment already submitted");
        paymentSubmitted[batchId][payeeRecord] = true;
        settlementRef = bridge.submitProviderPayment(batchId, recipient, paymentRecord);
        emit ProviderPaymentSubmitted(batchId, recipient, payeeRecord, settlementRef);
    }
}
