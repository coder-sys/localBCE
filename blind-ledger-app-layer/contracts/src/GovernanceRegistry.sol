// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract GovernanceRegistry {
    struct RootProposal {
        bytes32 key;
        bytes32 root;
        uint256 eta;
        uint256 approvals;
        bool exists;
        bool executed;
    }

    address public owner;
    uint256 public minDelay;
    uint256 public threshold;
    uint256 public signerCount;
    mapping(bytes32 => bytes32) public roots;
    mapping(address => bool) public signers;
    address[] public signerList;
    mapping(bytes32 => RootProposal) public rootProposals;
    mapping(bytes32 => mapping(address => bool)) public rootProposalApproved;

    event RootSet(bytes32 indexed key, bytes32 indexed root);
    event GovernanceConfigured(uint256 threshold, uint256 minDelay);
    event RootProposed(bytes32 indexed proposalId, bytes32 indexed key, bytes32 indexed root, uint256 eta);
    event RootApproved(bytes32 indexed proposalId, address indexed signer, uint256 approvals);
    event RootExecuted(bytes32 indexed proposalId, bytes32 indexed key, bytes32 indexed root);

    constructor() {
        owner = msg.sender;
        signers[msg.sender] = true;
        signerList.push(msg.sender);
        signerCount = 1;
        threshold = 1;
        minDelay = 0;
        emit GovernanceConfigured(threshold, minDelay);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlySigner() {
        require(signers[msg.sender], "not signer");
        _;
    }

    function configureGovernance(address[] calldata newSigners, uint256 newThreshold, uint256 newMinDelay) external onlyOwner {
        require(newSigners.length > 0, "no signers");
        require(newThreshold > 0 && newThreshold <= newSigners.length, "bad threshold");
        for (uint256 i = 0; i < signerList.length; i++) {
            signers[signerList[i]] = false;
        }
        delete signerList;
        for (uint256 i = 0; i < newSigners.length; i++) {
            address signer = newSigners[i];
            require(signer != address(0), "signer zero");
            require(!signers[signer], "duplicate signer");
            signers[signer] = true;
            signerList.push(signer);
        }
        signerCount = newSigners.length;
        threshold = newThreshold;
        minDelay = newMinDelay;
        emit GovernanceConfigured(threshold, minDelay);
    }

    function setRoot(bytes32 key, bytes32 root) external onlyOwner {
        require(_demoImmediateMode(), "timelock required");
        _setRoot(key, root);
    }

    function proposeRoot(bytes32 key, bytes32 root) external onlySigner returns (bytes32 proposalId) {
        require(key != bytes32(0), "key zero");
        require(root != bytes32(0), "root zero");
        proposalId = keccak256(abi.encodePacked("ROOT_PROPOSAL_V1", key, root, block.timestamp, msg.sender));
        require(!rootProposals[proposalId].exists, "proposal exists");
        RootProposal storage proposal = rootProposals[proposalId];
        proposal.key = key;
        proposal.root = root;
        proposal.eta = block.timestamp + minDelay;
        proposal.exists = true;
        _approve(proposalId, msg.sender);
        emit RootProposed(proposalId, key, root, proposal.eta);
    }

    function approveRoot(bytes32 proposalId) external onlySigner {
        require(rootProposals[proposalId].exists, "proposal missing");
        require(!rootProposals[proposalId].executed, "proposal executed");
        _approve(proposalId, msg.sender);
    }

    function executeRoot(bytes32 proposalId) external {
        RootProposal storage proposal = rootProposals[proposalId];
        require(proposal.exists, "proposal missing");
        require(!proposal.executed, "proposal executed");
        require(block.timestamp >= proposal.eta, "timelock active");
        require(proposal.approvals >= threshold, "insufficient approvals");
        proposal.executed = true;
        _setRoot(proposal.key, proposal.root);
        emit RootExecuted(proposalId, proposal.key, proposal.root);
    }

    function _approve(bytes32 proposalId, address signer) internal {
        if (!rootProposalApproved[proposalId][signer]) {
            rootProposalApproved[proposalId][signer] = true;
            rootProposals[proposalId].approvals += 1;
            emit RootApproved(proposalId, signer, rootProposals[proposalId].approvals);
        }
    }

    function _setRoot(bytes32 key, bytes32 root) internal {
        require(key != bytes32(0), "key zero");
        require(root != bytes32(0), "root zero");
        roots[key] = root;
        emit RootSet(key, root);
    }

    function _demoImmediateMode() internal view returns (bool) {
        return minDelay == 0 && threshold == 1 && signerCount == 1 && signers[owner];
    }
}

