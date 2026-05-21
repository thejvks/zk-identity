// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ReputationOracle
 * @notice Stores AI-computed reputation scores anchored to ZK nullifiers.
 *         The off-chain AI oracle signs a score and submits it here.
 *         No personal data is stored — only the score and nullifier hash.
 */
contract ReputationOracle is Ownable {

    // ─── State ────────────────────────────────────────────────────────────────

    /// Authorized oracle signers (off-chain AI service wallets)
    mapping(address => bool) public authorizedOracles;

    /// nullifierHash => reputation score (0–100)
    mapping(bytes32 => uint256) public scores;

    /// nullifierHash => last updated timestamp
    mapping(bytes32 => uint256) public lastUpdated;

    // ─── Events ───────────────────────────────────────────────────────────────

    event ScoreUpdated(bytes32 indexed nullifierHash, uint256 score, address oracle);
    event OracleAuthorized(address oracle, bool status);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error UnauthorizedOracle();
    error InvalidScore();
    error InvalidSignature();

    constructor() Ownable(msg.sender) {}

    // ─── Oracle Methods ───────────────────────────────────────────────────────

    /**
     * @notice Submit an AI-computed reputation score.
     * @param _nullifierHash  ZK identity nullifier (no personal data)
     * @param _score          Score 0–100
     * @param _signature      EIP-712 signature from authorized oracle
     */
    function submitScore(
        bytes32 _nullifierHash,
        uint256 _score,
        bytes calldata _signature
    ) external {
        if (!authorizedOracles[msg.sender]) revert UnauthorizedOracle();
        if (_score > 100) revert InvalidScore();

        // Verify oracle signed this exact (nullifier, score) pair
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(_nullifierHash, _score))
            )
        );
        address signer = _recoverSigner(messageHash, _signature);
        if (!authorizedOracles[signer]) revert InvalidSignature();

        scores[_nullifierHash]      = _score;
        lastUpdated[_nullifierHash] = block.timestamp;

        emit ScoreUpdated(_nullifierHash, _score, msg.sender);
    }

    /**
     * @notice Get reputation score for a nullifier.
     */
    function getScore(bytes32 _nullifierHash) external view returns (uint256) {
        return scores[_nullifierHash];
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function setOracleStatus(address _oracle, bool _status) external onlyOwner {
        authorizedOracles[_oracle] = _status;
        emit OracleAuthorized(_oracle, _status);
    }

    // ─── Internal ─────────────────────────────────────────────────────────────

    function _recoverSigner(bytes32 _hash, bytes calldata _sig)
        internal
        pure
        returns (address)
    {
        require(_sig.length == 65, "Bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(_sig.offset)
            s := calldataload(add(_sig.offset, 32))
            v := byte(0, calldataload(add(_sig.offset, 64)))
        }
        return ecrecover(_hash, v, r, s);
    }
}
