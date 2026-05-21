import { useState, useEffect } from "react";
import { ethers } from "ethers";
import { proveAge, proveUniqueness, generateSalt } from "../utils/zkProver";
import ZKIdentityABI from "../abi/ZKIdentity.json";
import deployments from "../../../deployments.json";

// ─── AI Reputation Fetch ──────────────────────────────────────────────────────

async function fetchAIReputation(nullifierHash) {
  const res = await fetch("/api/reputation", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ nullifierHash }),
  });
  const { score } = await res.json();
  return score;
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function Home() {
  const [wallet, setWallet]       = useState(null);
  const [status, setStatus]       = useState("idle"); // idle | proving | submitting | done | error
  const [message, setMessage]     = useState("");
  const [claims, setClaims]       = useState({ age: false, unique: false });
  const [reputationScore, setReputationScore] = useState(null);
  const [txHash, setTxHash]       = useState(null);

  const [formData, setFormData] = useState({
    birthYear: "",
    minAge: "18",
    claimType: "age",
  });

  // ─── Wallet ───────────────────────────────────────────────────────────────

  async function connectWallet() {
    if (!window.ethereum) {
      setMessage("Install MetaMask or a Web3 wallet to continue.");
      return;
    }
    try {
      const provider = new ethers.BrowserProvider(window.ethereum);
      await provider.send("eth_requestAccounts", []);
      const signer = await provider.getSigner();
      const address = await signer.getAddress();
      setWallet({ provider, signer, address });

      // Load existing claims
      await loadClaims(provider, address);
    } catch (err) {
      setMessage("Connection rejected.");
    }
  }

  async function loadClaims(provider, address) {
    const contract = new ethers.Contract(
      deployments.zkIdentity,
      ZKIdentityABI,
      provider
    );
    const ageVerified    = await contract.hasClaim(address, 1);
    const uniqueVerified = await contract.hasClaim(address, 2);
    setClaims({ age: ageVerified, unique: uniqueVerified });
  }

  // ─── Core Flow ────────────────────────────────────────────────────────────

  async function handleProveAndSubmit(e) {
    e.preventDefault();
    if (!wallet) return setMessage("Connect your wallet first.");

    try {
      setStatus("proving");
      setMessage("Generating ZK proof locally — your data stays on this device...");

      const salt = generateSalt();
      let zkResult;

      if (formData.claimType === "age") {
        zkResult = await proveAge({
          birthYear: parseInt(formData.birthYear),
          salt,
          minAge: parseInt(formData.minAge),
        });
      } else {
        // Derive a unique secret from the user's wallet signature
        const rawSig = await wallet.signer.signMessage(
          "ZK-Identity: Generate my unique identity secret. This never leaves your device."
        );
        const secret = BigInt(ethers.keccak256(rawSig));
        zkResult = await proveUniqueness({ secret, salt });
      }

      setMessage("✅ Proof generated! Fetching AI reputation score...");
      setStatus("submitting");

      // Fetch AI reputation score for this nullifier
      const repScore = await fetchAIReputation(zkResult.nullifierHash);
      setReputationScore(repScore);

      setMessage("Submitting proof to the blockchain...");

      // Submit on-chain
      const claimType = formData.claimType === "age" ? 1 : 2;
      const contract = new ethers.Contract(
        deployments.zkIdentity,
        ZKIdentityABI,
        wallet.signer
      );

      const { solidityArgs } = zkResult;
      const tx = await contract.verifyAndAttest(
        solidityArgs.nullifierHash,
        solidityArgs.commitmentHash,
        claimType,
        repScore,
        solidityArgs.proofA,
        solidityArgs.proofB,
        solidityArgs.proofC
      );

      setMessage("⏳ Waiting for transaction confirmation...");
      await tx.wait();
      setTxHash(tx.hash);

      setStatus("done");
      setMessage("🎉 Identity verified on-chain! No personal data was revealed.");
      await loadClaims(wallet.provider, wallet.address);

    } catch (err) {
      console.error(err);
      setStatus("error");
      setMessage(
        err.reason || err.message || "Something went wrong. Check the console."
      );
    }
  }

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <main style={{ maxWidth: 600, margin: "0 auto", padding: "2rem 1rem" }}>
      <h1>🔐 ZK-Identity</h1>
      <p style={{ color: "#666", marginTop: 4 }}>
        Prove who you are — without revealing anything about yourself.
      </p>

      {/* ── Wallet Connection ─────────────────────────────────────────── */}
      {!wallet ? (
        <button onClick={connectWallet} style={styles.btn}>
          Connect Wallet
        </button>
      ) : (
        <div style={styles.walletBadge}>
          🟢 {wallet.address.slice(0, 6)}...{wallet.address.slice(-4)}
        </div>
      )}

      {/* ── Existing Claims ───────────────────────────────────────────── */}
      {wallet && (
        <div style={styles.claimsRow}>
          <ClaimBadge label="Age ≥ 18" active={claims.age} />
          <ClaimBadge label="Unique Human" active={claims.unique} />
          {reputationScore !== null && (
            <ClaimBadge label={`Reputation: ${reputationScore}/100`} active={true} />
          )}
        </div>
      )}

      {/* ── Claim Form ────────────────────────────────────────────────── */}
      {wallet && status !== "done" && (
        <form onSubmit={handleProveAndSubmit} style={{ marginTop: 24 }}>
          <div style={styles.field}>
            <label>Claim Type</label>
            <select
              value={formData.claimType}
              onChange={(e) => setFormData({ ...formData, claimType: e.target.value })}
              style={styles.input}
            >
              <option value="age">Age Verification (prove age ≥ N)</option>
              <option value="unique">Unique Human (prove you're not a bot)</option>
            </select>
          </div>

          {formData.claimType === "age" && (
            <>
              <div style={styles.field}>
                <label>Birth Year (stays on your device)</label>
                <input
                  type="number"
                  placeholder="e.g. 1995"
                  min="1900"
                  max={new Date().getFullYear()}
                  value={formData.birthYear}
                  onChange={(e) => setFormData({ ...formData, birthYear: e.target.value })}
                  required
                  style={styles.input}
                />
              </div>
              <div style={styles.field}>
                <label>Minimum Age to Prove</label>
                <input
                  type="number"
                  min="1"
                  max="100"
                  value={formData.minAge}
                  onChange={(e) => setFormData({ ...formData, minAge: e.target.value })}
                  style={styles.input}
                />
              </div>
            </>
          )}

          <button
            type="submit"
            disabled={status === "proving" || status === "submitting"}
            style={{ ...styles.btn, marginTop: 16 }}
          >
            {status === "proving"    && "⚙️  Generating Proof..."}
            {status === "submitting" && "📡 Submitting..."}
            {status === "idle"       && "Generate ZK Proof & Verify"}
            {status === "error"      && "Try Again"}
          </button>
        </form>
      )}

      {/* ── Status Message ────────────────────────────────────────────── */}
      {message && (
        <div style={{ ...styles.msg, borderColor: status === "error" ? "#f87171" : "#4ade80" }}>
          {message}
        </div>
      )}

      {/* ── Success ───────────────────────────────────────────────────── */}
      {txHash && (
        <a
          href={`https://polygonscan.com/tx/${txHash}`}
          target="_blank"
          rel="noreferrer"
          style={{ display: "block", marginTop: 12, color: "#6366f1" }}
        >
          View transaction on PolygonScan ↗
        </a>
      )}
    </main>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function ClaimBadge({ label, active }) {
  return (
    <span style={{
      padding: "4px 12px",
      borderRadius: 999,
      fontSize: 13,
      background: active ? "#d1fae5" : "#f3f4f6",
      color: active ? "#065f46" : "#9ca3af",
      border: `1px solid ${active ? "#6ee7b7" : "#e5e7eb"}`,
    }}>
      {active ? "✓" : "○"} {label}
    </span>
  );
}

// ─── Styles ───────────────────────────────────────────────────────────────────

const styles = {
  btn: {
    padding: "10px 24px",
    background: "#6366f1",
    color: "#fff",
    border: "none",
    borderRadius: 8,
    fontSize: 15,
    cursor: "pointer",
    marginTop: 16,
  },
  walletBadge: {
    display: "inline-block",
    marginTop: 16,
    padding: "6px 14px",
    background: "#f0fdf4",
    border: "1px solid #86efac",
    borderRadius: 8,
    fontSize: 14,
    color: "#166534",
  },
  claimsRow: {
    display: "flex",
    gap: 8,
    flexWrap: "wrap",
    marginTop: 16,
  },
  field: {
    display: "flex",
    flexDirection: "column",
    gap: 6,
    marginBottom: 16,
  },
  input: {
    padding: "8px 12px",
    fontSize: 15,
    border: "1px solid #d1d5db",
    borderRadius: 8,
    outline: "none",
  },
  msg: {
    marginTop: 20,
    padding: 14,
    border: "1px solid",
    borderRadius: 8,
    fontSize: 14,
    background: "#f9fafb",
  },
};
