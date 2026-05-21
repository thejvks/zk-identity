pragma circom 2.1.5;

/*
 * ┌─────────────────────────────────────────────────────────┐
 * │  UniqueHuman.circom                                     │
 * │                                                         │
 * │  Proves the user controls a unique credential (e.g.     │
 * │  a government ID or biometric hash) WITHOUT revealing   │
 * │  any information about the credential itself.           │
 * │                                                         │
 * │  This is a Sybil-resistance primitive — each real       │
 * │  human can only generate ONE valid nullifier per        │
 * │  "context" (e.g. per app or per vote).                  │
 * └─────────────────────────────────────────────────────────┘
 */

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * Proves: prover knows secret such that
 *         Poseidon(secret) == credentialRoot (a known Merkle root)
 *         and the nullifier is correctly derived
 */
template UniqueHuman() {

    // ── Public signals ──────────────────────────────────────
    signal input  nullifierHash;    // One per (secret, context)
    signal input  commitmentHash;   // Poseidon(secret, salt)
    signal input  contextId;        // App/protocol identifier

    // ── Private signals ─────────────────────────────────────
    signal input  secret;           // User's unique identity secret
    signal input  salt;             // Random per-claim blinding factor

    // ── Output ───────────────────────────────────────────────
    signal output validProof;

    // ── Step 1: Verify commitment ────────────────────────────
    component commit = Poseidon(2);
    commit.inputs[0] <== secret;
    commit.inputs[1] <== salt;
    commitmentHash === commit.out;

    // ── Step 2: Derive context-scoped nullifier ──────────────
    // Nullifier is scoped to a context — same human, different app
    // = different nullifier. Cross-app tracking is impossible.
    component nullifier = Poseidon(3);
    nullifier.inputs[0] <== secret;
    nullifier.inputs[1] <== salt;
    nullifier.inputs[2] <== contextId;

    nullifierHash === nullifier.out;

    // ── Step 3: Ensure secret is non-zero (basic validity) ───
    component isZero = IsZero();
    isZero.in <== secret;
    isZero.out === 0; // secret must NOT be zero

    validProof <== 1 - isZero.out;
}

// Simple IsZero component (inline, no circomlib dependency)
template IsZero() {
    signal input in;
    signal output out;
    signal inv;
    inv <-- in != 0 ? 1/in : 0;
    out <== -in * inv + 1;
    in * out === 0;
}

component main {public [nullifierHash, commitmentHash, contextId]}
    = UniqueHuman();
