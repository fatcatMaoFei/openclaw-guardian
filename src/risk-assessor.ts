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
export function flattenParams(params: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const v of Object.values(params)) {
    if (typeof v === "string") parts.push(v);
    else if (v != null) parts.push(JSON.stringify(v));
  }
  return parts.join(" ");
}

/** Check if a keyword appears inside a quoted/commented context (grep, echo, sed, #) */
export function isQuotedOrCommented(haystack: string, keyword: string): boolean {
  const idx = haystack.indexOf(keyword);
  if (idx === -1) return false;
  // Only check context on the SAME LINE as the keyword
  const lineStart = haystack.lastIndexOf("\n", idx) + 1;
  const before = haystack.substring(lineStart, idx);
  if (/grep\s+["']?[^"']*$/.test(before)) return true;
  if (/echo\s+["']?[^"']*$/.test(before)) return true;
  if (/sed\s+["']?[^"']*$/.test(before)) return true;
  if (/^\s*#/.test(before) && before.includes("#")) return true;
  return false;
}

const HIGH_RISK_PATHS = ["/", "/home", "/etc", "/root", "/var", "/usr", "/boot", "/sys"];
const LOW_RISK_PATHS = ["/tmp", "/var/tmp", "/dev/null"];

/** Returns a multiplier based on path sensitivity: 1.5 for high-risk, 0.5 for low-risk, 1.0 default */
export function pathRiskMultiplier(params: Record<string, unknown>): number {
  const haystack = flattenParams(params);
  for (const p of HIGH_RISK_PATHS) {
    if (new RegExp(`(?:^|\\s|/)${p.replace("/", "\\/")}(?:\\s|/|$)`).test(haystack)) return 1.5;
  }
  for (const p of LOW_RISK_PATHS) {
    if (haystack.includes(p)) return 0.5;
  }
  return 1.0;
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
        // Reduce impact if keyword is in a quoted/commented context
        const effective = isQuotedOrCommented(haystack, keyword.toLowerCase())
          ? Math.round(delta * 0.3)
          : delta;
        score += effective;
        matchedKeywords.push(keyword);
      }
    }
  }

  // Apply path sensitivity multiplier
  score = Math.round(score * pathRiskMultiplier(params));

  // Clamp 0–100
  score = Math.max(0, Math.min(100, score));

  const tier: RiskResult["tier"] =
    score <= thresholds.low ? "fast" : score <= thresholds.high ? "light" : "full";

  return { score, tier, matchedKeywords, toolPolicy };
}
