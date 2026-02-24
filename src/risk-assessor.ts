/**
 * Risk Assessor — keyword-based rule engine for tool call risk scoring.
 * Returns a score from 0–100. Zero-latency, no external calls.
 */

export type Policy = {
  tool: string;
  baseScore: number;
  keywords?: Record<string, number>;
};

export type Policies = {
  enabled: boolean;
  thresholds: { low: number; high: number };
  guardianModel: string;
  policies: Policy[];
  voting: {
    lightReview: { guardians: number; threshold: number };
    fullVote: { guardians: number; threshold: number };
  };
  trustBudget: { enabled: boolean; autoDowngradeAfter: number };
};

export type RiskResult = {
  score: number;
  tier: "fast" | "light" | "full";
  matchedKeywords: string[];
  toolPolicy: Policy | null;
};

/** Flatten all params into a single searchable string */
function flattenParams(params: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const v of Object.values(params)) {
    if (typeof v === "string") parts.push(v);
    else if (v != null) parts.push(JSON.stringify(v));
  }
  return parts.join(" ");
}

export function assessRisk(
  toolName: string,
  params: Record<string, unknown>,
  policies: Policies,
): RiskResult {
  const { thresholds } = policies;

  // Find matching policy (exact match or wildcard)
  const toolPolicy =
    policies.policies.find((p) => p.tool === toolName) ??
    policies.policies.find((p) => p.tool === "*") ??
    null;

  let score = toolPolicy?.baseScore ?? 10;
  const matchedKeywords: string[] = [];

  if (toolPolicy?.keywords) {
    const haystack = flattenParams(params).toLowerCase();
    for (const [keyword, delta] of Object.entries(toolPolicy.keywords)) {
      if (haystack.includes(keyword.toLowerCase())) {
        score += delta;
        matchedKeywords.push(keyword);
      }
    }
  }

  // Clamp 0–100
  score = Math.max(0, Math.min(100, score));

  const tier: RiskResult["tier"] =
    score <= thresholds.low ? "fast" : score <= thresholds.high ? "light" : "full";

  return { score, tier, matchedKeywords, toolPolicy };
}
