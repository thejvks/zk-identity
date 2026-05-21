/**
 * zkProver.js — Client-side ZK proof generation
 *
 * Uses snarkjs (WASM) to generate Groth16 proofs entirely in the browser.
 * No private data ever leaves the user's device.
 *
 * Usage:
 *   import { proveAge, proveUniqueness } from './utils/zkProver';
 *   const { proof, publicSignals } = await proveAge({ birthYear: 1995, salt, minAge: 18 });
 */

import { groth16 } from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { ethers } from "ethers";

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} AgeProofInput
 * @property {number} birthYear    - User's birth year (never sent anywhere)
 * @property {bigint} salt         - Random 256-bit blinding factor
 * @property {number} minAge       - Minimum age threshold (e.g. 18)
 * @property {number} [currentYear]- Defaults to current year
 */

/**
 * @typedef {Object} ZKProofResult
 * @property {Object} proof          - Groth16 proof (a, b, c)
 * @property {string[]} publicSignals - Public outputs
 * @property {string} nullifierHash  - Hex nullifier for on-chain submission
 * @property {string} commitmentHash - Hex commitment for on-chain submission
 * @property {Object} solidityArgs   - Ready for ethers.js contract call
 */

// ─── Helpers ──────────────────────────────────────────────────────────────────

let poseidon = null;

async function getPoseidon() {
  if (!poseidon) poseidon = await buildPoseidon();
  return poseidon;
}

/** Generate a cryptographically random salt */
export function generateSalt() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return BigInt("0x" + Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(""));
}

/** Convert a Poseidon field element to a 0x-prefixed hex string */
function fieldToHex(fieldElem) {
  const arr = poseidon.F.toObject(fieldElem);
  return ethers.toBeHex(arr, 32);
}

// ─── Age Proof ────────────────────────────────────────────────────────────────

/**
 * Generate a ZK proof that the user is over `minAge` years old.
 * @param {AgeProofInput} params
 * @returns {Promise<ZKProofResult>}
 */
export async function proveAge({ birthYear, salt, minAge = 18, currentYear }) {
  const _poseidon = await getPoseidon();
  const _currentYear = currentYear ?? new Date().getFullYear();
  const _salt = salt ?? generateSalt();

  // Compute commitment = Poseidon(birthYear, salt)
  const commitmentField = _poseidon([BigInt(birthYear), _salt]);
  const commitmentHash = fieldToHex(commitmentField);

  // Compute nullifier = Poseidon(birthYear, salt, claimType=1)
  const nullifierField = _poseidon([BigInt(birthYear), _salt, 1n]);
  const nullifierHash = fieldToHex(nullifierField);

  const input = {
    nullifierHash:  BigInt(nullifierHash).toString(),
    commitmentHash: BigInt(commitmentHash).toString(),
    minAge:         minAge.toString(),
    currentYear:    _currentYear.toString(),
    birthYear:      birthYear.toString(),
    salt:           _salt.toString(),
  };

  console.log("🔐 Generating ZK proof... (may take 5–15 seconds)");
  const { proof, publicSignals } = await groth16.fullProve(
    input,
    "/circuits/AgeVerifier.wasm",      // Served from /public/circuits/
    "/circuits/AgeVerifier_final.zkey"
  );

  return {
    proof,
    publicSignals,
    nullifierHash,
    commitmentHash,
    solidityArgs: proofToSolidityArgs(proof, publicSignals, nullifierHash, commitmentHash),
  };
}

// ─── Uniqueness Proof ─────────────────────────────────────────────────────────

/**
 * Generate a ZK proof of unique personhood for a given app context.
 * @param {Object} params
 * @param {bigint} params.secret     - User's unique identity secret
 * @param {bigint} [params.salt]     - Random blinding factor
 * @param {bigint} [params.contextId]- App identifier (default: 0n for global)
 * @returns {Promise<ZKProofResult>}
 */
export async function proveUniqueness({ secret, salt, contextId = 0n }) {
  const _poseidon = await getPoseidon();
  const _salt = salt ?? generateSalt();

  const commitmentField = _poseidon([secret, _salt]);
  const commitmentHash = fieldToHex(commitmentField);

  const nullifierField = _poseidon([secret, _salt, contextId]);
  const nullifierHash = fieldToHex(nullifierField);

  const input = {
    nullifierHash:  BigInt(nullifierHash).toString(),
    commitmentHash: BigInt(commitmentHash).toString(),
    contextId:      contextId.toString(),
    secret:         secret.toString(),
    salt:           _salt.toString(),
  };

  console.log("🔐 Generating uniqueness proof...");
  const { proof, publicSignals } = await groth16.fullProve(
    input,
    "/circuits/UniqueHuman.wasm",
    "/circuits/UniqueHuman_final.zkey"
  );

  return {
    proof,
    publicSignals,
    nullifierHash,
    commitmentHash,
    solidityArgs: proofToSolidityArgs(proof, publicSignals, nullifierHash, commitmentHash),
  };
}

// ─── Format for Solidity ──────────────────────────────────────────────────────

/**
 * Convert a snarkjs proof to the format expected by the Solidity verifier.
 * @returns {{ proofA, proofB, proofC }} Ready for ethers.js contract call
 */
function proofToSolidityArgs(proof, publicSignals, nullifierHash, commitmentHash) {
  return {
    nullifierHash,
    commitmentHash,
    proofA: [proof.pi_a[0], proof.pi_a[1]],
    proofB: [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ],
    proofC: [proof.pi_c[0], proof.pi_c[1]],
  };
}

// ─── Verify Proof Off-Chain ───────────────────────────────────────────────────

/**
 * Verify a proof locally before submitting on-chain (saves gas on invalid proofs).
 */
export async function verifyProofLocally(proof, publicSignals, verificationKeyPath) {
  const vkeyRes = await fetch(verificationKeyPath);
  const vkey = await vkeyRes.json();
  const valid = await groth16.verify(vkey, publicSignals, proof);
  return valid;
}
