const { expect } = require("chai");
const { ethers } = require("hardhat");

/**
 * ZKIdentity Test Suite
 *
 * NOTE: The ZK proof verification tests use mock proofs.
 * For real proof tests, generate proofs with snarkjs first:
 *   const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey)
 */
describe("ZKIdentity", function () {
  let zkIdentity, reputationOracle;
  let owner, user1, user2;
  let mockVerifier;

  // ── Test fixtures ─────────────────────────────────────────────────────────

  const CLAIM_TYPE_AGE    = 1;
  const CLAIM_TYPE_UNIQUE = 2;

  const mockNullifier   = ethers.keccak256(ethers.toUtf8Bytes("nullifier_1"));
  const mockCommitment  = ethers.keccak256(ethers.toUtf8Bytes("commitment_1"));
  const mockRepScore    = 72;

  const ZERO_PROOF_A = [0n, 0n];
  const ZERO_PROOF_B = [[0n, 0n], [0n, 0n]];
  const ZERO_PROOF_C = [0n, 0n];

  // ── Deploy ────────────────────────────────────────────────────────────────

  beforeEach(async function () {
    [owner, user1, user2] = await ethers.getSigners();

    // Deploy a mock verifier that always returns true
    const MockVerifier = await ethers.getContractFactory("MockGroth16Verifier");
    mockVerifier = await MockVerifier.deploy(true); // true = always valid

    const ZKIdentity = await ethers.getContractFactory("ZKIdentity");
    zkIdentity = await ZKIdentity.deploy();

    const ReputationOracle = await ethers.getContractFactory("ReputationOracle");
    reputationOracle = await ReputationOracle.deploy();

    // Register mock verifier for age claims
    await zkIdentity.registerVerifier(CLAIM_TYPE_AGE, await mockVerifier.getAddress());
    await zkIdentity.registerVerifier(CLAIM_TYPE_UNIQUE, await mockVerifier.getAddress());
  });

  // ── Core Tests ────────────────────────────────────────────────────────────

  describe("Attestation", function () {
    it("should verify and attest a valid age claim", async function () {
      await expect(
        zkIdentity.connect(user1).verifyAndAttest(
          mockNullifier,
          mockCommitment,
          CLAIM_TYPE_AGE,
          mockRepScore,
          ZERO_PROOF_A,
          ZERO_PROOF_B,
          ZERO_PROOF_C
        )
      )
        .to.emit(zkIdentity, "IdentityVerified")
        .withArgs(user1.address, mockNullifier, CLAIM_TYPE_AGE, mockRepScore);
    });

    it("should set the hasClaim flag correctly", async function () {
      await zkIdentity.connect(user1).verifyAndAttest(
        mockNullifier, mockCommitment,
        CLAIM_TYPE_AGE, mockRepScore,
        ZERO_PROOF_A, ZERO_PROOF_B, ZERO_PROOF_C
      );

      expect(await zkIdentity.hasClaim(user1.address, CLAIM_TYPE_AGE)).to.equal(true);
      expect(await zkIdentity.hasClaim(user1.address, CLAIM_TYPE_UNIQUE)).to.equal(false);
    });

    it("should increment totalAttestations", async function () {
      expect(await zkIdentity.totalAttestations()).to.equal(0);
      await zkIdentity.connect(user1).verifyAndAttest(
        mockNullifier, mockCommitment,
        CLAIM_TYPE_AGE, 80,
        ZERO_PROOF_A, ZERO_PROOF_B, ZERO_PROOF_C
      );
      expect(await zkIdentity.totalAttestations()).to.equal(1);
    });
  });

  // ── Replay Protection ─────────────────────────────────────────────────────

  describe("Replay protection", function () {
    it("should revert on duplicate nullifier", async function () {
      await zkIdentity.connect(user1).verifyAndAttest(
        mockNullifier, mockCommitment,
        CLAIM_TYPE_AGE, 50,
        ZERO_PROOF_A, ZERO_PROOF_B, ZERO_PROOF_C
      );

      await expect(
        zkIdentity.connect(user2).verifyAndAttest(
          mockNullifier,                              // Same nullifier
          ethers.keccak256(ethers.toUtf8Bytes("c2")),
          CLAIM_TYPE_AGE, 50,
          ZERO_PROOF_A, ZERO_PROOF_B, ZERO_PROOF_C
        )
      ).to.be.revertedWithCustomError(zkIdentity, "NullifierAlreadyUsed");
    });
  });

  // ── Revocation ────────────────────────────────────────────────────────────

  describe("Revocation", function () {
    beforeEach(async function () {
      await zkIdentity.connect(user1).verifyAndAttest(
        mockNullifier, mockCommitment,
        CLAIM_TYPE_AGE, 50,
        ZERO_PROOF_A, ZERO_PROOF_B, ZERO_PROOF_C
      );
    });

    it("should allow self-revocation", async function () {
      await expect(zkIdentity.connect(user1).revokeAttestation(mockNullifier))
        .to.emit(zkIdentity, "AttestationRevoked")
        .withArgs(user1.address, mockNullifier);

      const attestation = await zkIdentity.getAttestation(mockNullifier);
      expect(attestation.revoked).to.equal(true);
    });

    it("should prevent others from revoking your attestation", async function () {
      await expect(
        zkIdentity.connect(user2).revokeAttestation(mockNullifier)
      ).to.be.revertedWithCustomError(zkIdentity, "UnauthorizedRevocation");
    });
  });

  // ── Verifier Registration ─────────────────────────────────────────────────

  describe("Verifier management", function () {
    it("should revert if no verifier registered", async function () {
      const unknullifier = ethers.keccak256(ethers.toUtf8Bytes("other_nullifier"));
      await expect(
        zkIdentity.connect(user1).verifyAndAttest(
          unknullifier, mockCommitment,
          99,  // Unregistered claim type
          50,
          ZERO_PROOF_A, ZERO_PROOF_B, ZERO_PROOF_C
        )
      ).to.be.revertedWithCustomError(zkIdentity, "VerifierNotRegistered");
    });

    it("should only allow owner to register verifiers", async function () {
      await expect(
        zkIdentity.connect(user1).registerVerifier(5, await mockVerifier.getAddress())
      ).to.be.revertedWithCustomError(zkIdentity, "OwnableUnauthorizedAccount");
    });
  });

  // ── Reputation Oracle ─────────────────────────────────────────────────────

  describe("ReputationOracle", function () {
    it("should reject scores > 100", async function () {
      await reputationOracle.setOracleStatus(owner.address, true);
      const sig = await signScore(owner, mockNullifier, 150);
      await expect(
        reputationOracle.submitScore(mockNullifier, 150, sig)
      ).to.be.revertedWithCustomError(reputationOracle, "InvalidScore");
    });

    it("should reject unauthorized oracles", async function () {
      const sig = await signScore(user1, mockNullifier, 75);
      await expect(
        reputationOracle.connect(user1).submitScore(mockNullifier, 75, sig)
      ).to.be.revertedWithCustomError(reputationOracle, "UnauthorizedOracle");
    });
  });

  // ── Helpers ───────────────────────────────────────────────────────────────

  async function signScore(signer, nullifierHash, score) {
    const messageHash = ethers.keccak256(
      ethers.solidityPacked(["bytes32", "uint256"], [nullifierHash, score])
    );
    return signer.signMessage(ethers.getBytes(messageHash));
  }
});
