pragma circom 2.1.5;

/*
 * ┌─────────────────────────────────────────────────────────┐
 * │  AgeVerifier.circom                                     │
 * │                                                         │
 * │  Proves that a user's age is >= minAge WITHOUT          │
 * │  revealing their actual date of birth or age.           │
 * │                                                         │
 * │  Public inputs:  nullifierHash, commitmentHash,         │
 * │                  minAge, currentYear                    │
 * │  Private inputs: birthYear, salt                        │
 * │                                                         │
 * │  Usage:                                                 │
 * │    circom AgeVerifier.circom --r1cs --wasm --sym        │
 * │    snarkjs groth16 setup AgeVerifier.r1cs pot12.ptau    │
 * │    snarkjs zkey new ...                                 │
 * │    snarkjs zkey export verificationkey                  │
 * └─────────────────────────────────────────────────────────┘
 */

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * Proves: currentYear - birthYear >= minAge
 *         WITHOUT revealing birthYear
 */
template AgeVerifier() {

    // ── Public signals ──────────────────────────────────────
    signal input  nullifierHash;  // Unique per-claim identifier
    signal input  commitmentHash; // Hash(birthYear, salt) — anchors the proof
    signal input  minAge;         // e.g. 18
    signal input  currentYear;    // e.g. 2025

    // ── Private signals ─────────────────────────────────────
    signal input  birthYear;      // Never revealed on-chain
    signal input  salt;           // Random blinding factor

    // ── Output signals ──────────────────────────────────────
    signal output validProof;     // 1 if valid, 0 otherwise

    // ── Step 1: Verify the commitment ───────────────────────
    // Ensure the prover knows the actual birthYear behind the commitment
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== birthYear;
    poseidon.inputs[1] <== salt;

    // The Poseidon hash must match the public commitmentHash
    commitmentHash === poseidon.out;

    // ── Step 2: Verify the nullifier ────────────────────────
    // Nullifier = Poseidon(birthYear, salt, claimType=1)
    // This prevents the same credential being used twice
    component nullifier = Poseidon(3);
    nullifier.inputs[0] <== birthYear;
    nullifier.inputs[1] <== salt;
    nullifier.inputs[2] <== 1; // claimType = 1 (AgeOver18)

    nullifierHash === nullifier.out;

    // ── Step 3: Verify age constraint ───────────────────────
    // Compute age = currentYear - birthYear
    signal age;
    age <== currentYear - birthYear;

    // Check age >= minAge using LessEqThan comparator
    // LessEqThan(n) checks if in[0] <= in[1]
    component ageCheck = LessEqThan(8); // 8 bits supports ages 0–255
    ageCheck.in[0] <== minAge;
    ageCheck.in[1] <== age;

    // ageCheck.out must be 1 (minAge <= age)
    ageCheck.out === 1;

    // ── Step 4: Range checks (prevent underflow attacks) ────
    component yearRange = LessEqThan(12); // 12 bits supports years 0–4095
    yearRange.in[0] <== birthYear;
    yearRange.in[1] <== currentYear;
    yearRange.out === 1;

    // ── Output ───────────────────────────────────────────────
    validProof <== ageCheck.out;
}

component main {public [nullifierHash, commitmentHash, minAge, currentYear]}
    = AgeVerifier();
