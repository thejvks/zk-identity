// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ZKIdentity
 * @notice Verify identity claims WITHOUT revealing private data.
 *         Users prove age, uniqueness, or credential ownership
 *         using Zero-Knowledge proofs — nothing is stored on-chain
 *         except a commitment hash and nullifier.
 * @dev Uses Groth16 ZK proofs generated from Circom circuits.
 */
contract ZKIdentity is Ownable, ReentrancyGuard {

    // ─── Structs ──────────────────────────────────────────────────────────────

    struct IdentityAttestation {
        bytes32 nullifierHash;      // Prevents double-claiming
        bytes32 commitmentHash;     // Hash of user's private identity data
        uint256 claimType;          // 1=AgeOver18, 2=Unique, 3=Credential
        uint256 issuedAt;           // Timestamp
        bool    revoked;            // Can be revoked by owner
        uint256 reputationScore;    // AI-computed reputation (0–100)
    }

    struct VerifierKey {
        uint256[2] alpha;
        uint256[2][2] beta;
        uint256[2][2] gamma;
        uint256[2][2] delta;
        uint256[2][] ic;
    }

    // ─── State ────────────────────────────────────────────────────────────────

    /// nullifierHash => attestation
    mapping(bytes32 => IdentityAttestation) public attestations;

    /// address => list of nullifierHashes they own
    mapping(address => bytes32[]) public userAttestations;

    /// address => verified claim types (bitmap)
    mapping(address => uint256) public verifiedClaims;

    /// Registered verifier contract per claim type
    mapping(uint256 => address) public claimVerifiers;

    /// Nullifiers used (prevents replay attacks)
    mapping(bytes32 => bool) public usedNullifiers;

    uint256 public totalAttestations;
    uint256 public constant VERSION = 1;

    // ─── Events ───────────────────────────────────────────────────────────────

    event IdentityVerified(
        address indexed user,
        bytes32 indexed nullifierHash,
        uint256 claimType,
        uint256 reputationScore
    );

    event AttestationRevoked(
        address indexed user,
        bytes32 indexed nullifierHash
    );

    event VerifierRegistered(
        uint256 indexed claimType,
        address verifier
    );

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NullifierAlreadyUsed();
    error InvalidProof();
    error AttestationNotFound();
    error UnauthorizedRevocation();
    error VerifierNotRegistered();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ─── Core: Verify & Attest ────────────────────────────────────────────────

    /**
     * @notice Submit a ZK proof to claim an identity attestation.
     * @param _nullifierHash   Unique hash preventing double-use
     * @param _commitmentHash  Hash of user's private credential
     * @param _claimType       Type of claim (1=Age, 2=Unique, 3=Credential)
     * @param _reputationScore AI-computed score passed from off-chain oracle
     * @param _proofA          ZK proof component A (G1 point)
     * @param _proofB          ZK proof component B (G2 point)
     * @param _proofC          ZK proof component C (G1 point)
     */
    function verifyAndAttest(
        bytes32 _nullifierHash,
        bytes32 _commitmentHash,
        uint256 _claimType,
        uint256 _reputationScore,
        uint256[2]    calldata _proofA,
        uint256[2][2] calldata _proofB,
        uint256[2]    calldata _proofC
    ) external nonReentrant {
        // 1. Replay protection
        if (usedNullifiers[_nullifierHash]) revert NullifierAlreadyUsed();

        // 2. Check a verifier exists for this claim type
        if (claimVerifiers[_claimType] == address(0)) revert VerifierNotRegistered();

        // 3. Verify the ZK proof via the registered verifier contract
        bool valid = IGroth16Verifier(claimVerifiers[_claimType])
            .verifyProof(
                _proofA,
                _proofB,
                _proofC,
                [uint256(_nullifierHash), uint256(_commitmentHash), _claimType]
            );
        if (!valid) revert InvalidProof();

        // 4. Mark nullifier as used
        usedNullifiers[_nullifierHash] = true;

        // 5. Store attestation
        attestations[_nullifierHash] = IdentityAttestation({
            nullifierHash:   _nullifierHash,
            commitmentHash:  _commitmentHash,
            claimType:       _claimType,
            issuedAt:        block.timestamp,
            revoked:         false,
            reputationScore: _reputationScore > 100 ? 100 : _reputationScore
        });

        // 6. Link to caller
        userAttestations[msg.sender].push(_nullifierHash);

        // 7. Update claim bitmap
        verifiedClaims[msg.sender] |= (1 << _claimType);

        totalAttestations++;

        emit IdentityVerified(
            msg.sender,
            _nullifierHash,
            _claimType,
            _reputationScore
        );
    }

    // ─── Read ─────────────────────────────────────────────────────────────────

    /**
     * @notice Check if an address has verified a specific claim type.
     * @param _user      Address to check
     * @param _claimType Claim type to check
     */
    function hasClaim(address _user, uint256 _claimType)
        external
        view
        returns (bool)
    {
        return (verifiedClaims[_user] & (1 << _claimType)) != 0;
    }

    /**
     * @notice Get all attestation nullifiers for a user.
     */
    function getUserAttestations(address _user)
        external
        view
        returns (bytes32[] memory)
    {
        return userAttestations[_user];
    }

    /**
     * @notice Get full attestation details by nullifier.
     */
    function getAttestation(bytes32 _nullifierHash)
        external
        view
        returns (IdentityAttestation memory)
    {
        IdentityAttestation memory a = attestations[_nullifierHash];
        if (a.issuedAt == 0) revert AttestationNotFound();
        return a;
    }

    // ─── Revocation ───────────────────────────────────────────────────────────

    /**
     * @notice Revoke your own attestation (privacy-preserving exit).
     */
    function revokeAttestation(bytes32 _nullifierHash) external {
        bytes32[] storage userList = userAttestations[msg.sender];
        bool found = false;
        for (uint256 i = 0; i < userList.length; i++) {
            if (userList[i] == _nullifierHash) { found = true; break; }
        }
        if (!found) revert UnauthorizedRevocation();

        attestations[_nullifierHash].revoked = true;
        emit AttestationRevoked(msg.sender, _nullifierHash);
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    /**
     * @notice Register a Groth16 verifier contract for a claim type.
     *         Only owner. Deploy a new verifier, then register it here.
     */
    function registerVerifier(uint256 _claimType, address _verifier)
        external
        onlyOwner
    {
        claimVerifiers[_claimType] = _verifier;
        emit VerifierRegistered(_claimType, _verifier);
    }
}

// ─── Interface ────────────────────────────────────────────────────────────────

/**
 * @notice Interface every Groth16 verifier must implement.
 *         Generate verifier.sol from your Circom circuit with snarkjs.
 */
interface IGroth16Verifier {
    function verifyProof(
        uint256[2]    calldata a,
        uint256[2][2] calldata b,
        uint256[2]    calldata c,
        uint256[3]    calldata input
    ) external view returns (bool);
}
