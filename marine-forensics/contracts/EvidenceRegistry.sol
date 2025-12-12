// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EvidenceRegistry {

    struct Evidence {
        bytes32 hashValue;
        uint256 timestamp;
        address submittedBy;
    }

    mapping(bytes32 => Evidence) public evidences;

    event EvidenceSubmitted(bytes32 evidenceId, bytes32 hashValue, uint256 timestamp, address submittedBy);

    function submitEvidence(bytes32 evidenceId, bytes32 hashValue) public {
        evidences[evidenceId] = Evidence(hashValue, block.timestamp, msg.sender);
        emit EvidenceSubmitted(evidenceId, hashValue, block.timestamp, msg.sender);
    }

    function getEvidence(bytes32 evidenceId)
        public view
        returns(bytes32 hashValue, uint256 timestamp, address submittedBy)
    {
        Evidence memory e = evidences[evidenceId];
        return (e.hashValue, e.timestamp, e.submittedBy);
    }
}
