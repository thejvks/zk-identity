/**
 * /api/reputation — AI-Powered Reputation Scoring
 *
 * Takes a ZK nullifier hash (no personal data) and computes
 * an on-chain reputation score using an LLM as the reasoning engine.
 *
 * In production: enrich with on-chain data (wallet age, tx count,
 * DeFi activity, governance votes) passed as anonymous signals.
 * The nullifier links the score to the identity without revealing
 * who the identity is.
 */

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { nullifierHash, onChainSignals } = req.body;

  if (!nullifierHash) {
    return res.status(400).json({ error: "nullifierHash is required" });
  }

  try {
    // ── Fetch anonymous on-chain signals ──────────────────────────────────
    // In production: fetch real signals from an indexer (The Graph, Alchemy)
    const signals = onChainSignals || {
      walletAgeMonths:    Math.floor(Math.random() * 36) + 1,
      totalTransactions:  Math.floor(Math.random() * 200),
      uniqueProtocols:    Math.floor(Math.random() * 15),
      governanceVotes:    Math.floor(Math.random() * 5),
      hasENS:             Math.random() > 0.6,
      hasGitHubAttestation: Math.random() > 0.7,
    };

    // ── Ask LLM to compute a reputation score ──────────────────────────
    const prompt = buildReputationPrompt(signals);

    const aiResponse = await fetch(process.env.LLM_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.LLM_API_KEY}`,
      },
      body: JSON.stringify({
        model: process.env.LLM_MODEL || "gpt-4",
        max_tokens: 256,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    const aiData = await aiResponse.json();
    const rawText = aiData.content?.[0]?.text || "50";

    // Extract a number from the response
    const match = rawText.match(/\b(\d{1,3})\b/);
    let score = match ? parseInt(match[1]) : 50;
    score = Math.max(0, Math.min(100, score)); // Clamp to [0, 100]

    return res.status(200).json({
      score,
      signals, // Return signals for UI display (optional)
      computedAt: new Date().toISOString(),
    });

  } catch (err) {
    console.error("Reputation API error:", err);
    return res.status(500).json({ error: "Failed to compute reputation score", score: 50 });
  }
}

// ─── Prompt Builder ───────────────────────────────────────────────────────────

function buildReputationPrompt(signals) {
  return `You are a Web3 reputation scoring engine. Analyze these ANONYMOUS on-chain signals and output a single integer reputation score between 0 and 100.

SIGNALS (no personal data, no wallet address):
- Wallet age: ${signals.walletAgeMonths} months
- Total transactions: ${signals.totalTransactions}
- Unique protocols interacted with: ${signals.uniqueProtocols}
- Governance votes cast: ${signals.governanceVotes}
- Has ENS name: ${signals.hasENS}
- Has GitHub attestation: ${signals.hasGitHubAttestation}

SCORING RUBRIC:
- 0–20:  Brand new or nearly inactive wallet
- 21–40: Some activity but limited protocol diversity
- 41–60: Moderate user with consistent on-chain history
- 61–80: Active participant in multiple protocols/governance
- 81–100: Power user with rich, diverse, long-term on-chain history

Respond with ONLY a single integer. No explanation. No punctuation. Just the number.`;
}
