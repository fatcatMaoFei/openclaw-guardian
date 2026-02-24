/**
 * Guardian Voter — rule-based guardian evaluation with optional LLM review.
 *
 * Since plugins cannot call sessions_spawn, guardian evaluation uses:
 * 1. Primary: rule-based keyword analysis (zero latency, always available)
 * 2. Optional: LLM API call via the plugin runtime (if available)
 *
 * Supports parallel execution with early-abort for full vote mode.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { RiskResult, Policies } from "./risk-assessor.js";

export type Vote = {
  guardian: string;
  approve: boolean;
  confidence: number;
  reason: string;
  method: "rule" | "llm";
};

export type VoteResult = {
  approved: boolean;
  votes: Vote[];
  reason: string;
  tier: "fast" | "light" | "full";
};

type GuardianSpec = {
  name: string;
  promptFile: string;
  /** Rule-based keywords that trigger rejection from this guardian's perspective */
  rejectPatterns: RegExp[];
};

const GUARDIANS: GuardianSpec[] = [
  {
    name: "safety",
    promptFile: "safety.md",
    rejectPatterns: [
      /rm\s+(-rf?|--recursive)\s+[\/~]/i,
      /mkfs\b/i,
      /dd\s+if=/i,
      />\s*\/dev\//i,
      /shutdown|reboot|init\s+[06]/i,
      /kill\s+-9\s+1\b/i,
      /systemctl\s+(stop|disable)\s+(sshd|network|docker)/i,
    ],
  },
  {
    name: "privacy",
    promptFile: "privacy.md",
    rejectPatterns: [
      /cat\s+.*\.(env|pem|key)\b/i,
      /id_rsa|id_ed25519/i,
      /\/etc\/shadow/i,
      /AWS_SECRET|PRIVATE_KEY|api[_-]?key|password\s*[:=]/i,
      /\.ssh\/.*config/i,
    ],
  },
  {
    name: "permission",
    promptFile: "permission.md",
    rejectPatterns: [
      /sudo\s+/i,
      /chmod\s+[47]77/i,
      /chown\s+root/i,
      /usermod|useradd|userdel/i,
      /visudo/i,
      /\/etc\/sudoers/i,
    ],
  },
  {
    name: "reversibility",
    promptFile: "reversibility.md",
    rejectPatterns: [
      /rm\s+(-rf?|--recursive)/i,
      /DROP\s+(TABLE|DATABASE)/i,
      /TRUNCATE\s+/i,
      />\s+[^\s|]/i, // overwrite redirect
      /format\s+/i,
    ],
  },
];

const COMPREHENSIVE = GUARDIANS.find((g) => g.name === "safety")!; // fallback

let _promptCache: Map<string, string> | null = null;

function loadPrompt(name: string): string {
  if (!_promptCache) _promptCache = new Map();
  if (_promptCache.has(name)) return _promptCache.get(name)!;
  try {
    const guardiansDir = join(dirname(fileURLToPath(import.meta.url)), "..", "guardians");
    const content = readFileSync(join(guardiansDir, name), "utf-8");
    _promptCache.set(name, content);
    return content;
  } catch {
    return `You are a ${name.replace(".md", "")} guardian. Evaluate the tool call for safety.`;
  }
}

/** Rule-based guardian evaluation — zero latency */
function ruleBasedVote(
  guardian: GuardianSpec,
  toolName: string,
  params: Record<string, unknown>,
): Vote {
  const haystack = [toolName, ...Object.values(params).map((v) => (typeof v === "string" ? v : JSON.stringify(v ?? "")))].join(" ");

  for (const pattern of guardian.rejectPatterns) {
    if (pattern.test(haystack)) {
      return {
        guardian: guardian.name,
        approve: false,
        confidence: 0.8,
        reason: `Rule match: ${pattern.source}`,
        method: "rule",
      };
    }
  }

  return {
    guardian: guardian.name,
    approve: true,
    confidence: 0.7,
    reason: "No dangerous patterns detected",
    method: "rule",
  };
}

/** Try LLM-based evaluation via plugin runtime (optional) */
async function llmVote(
  guardian: GuardianSpec,
  toolName: string,
  params: Record<string, unknown>,
  runtime: any,
  model: string,
): Promise<Vote | null> {
  // Check if runtime provides LLM completion
  const complete =
    runtime?.llm?.complete ??
    runtime?.llm?.chat ??
    runtime?.complete ??
    null;

  if (typeof complete !== "function") return null;

  const systemPrompt = loadPrompt(guardian.promptFile);
  const userMessage = `Tool: ${toolName}\nParameters: ${JSON.stringify(params, null, 2)}`;

  try {
    const response = await Promise.race([
      complete({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userMessage },
        ],
        max_tokens: 200,
      }),
      new Promise<null>((_, reject) => setTimeout(() => reject(new Error("timeout")), 5000)),
    ]);

    if (!response) return null;

    const text = typeof response === "string" ? response : response?.content ?? response?.text ?? "";
    const match = text.match(/\{[^}]+\}/);
    if (!match) return null;

    const parsed = JSON.parse(match[0]);
    return {
      guardian: guardian.name,
      approve: !!parsed.approve,
      confidence: typeof parsed.confidence === "number" ? parsed.confidence : 0.5,
      reason: parsed.reason ?? "LLM evaluation",
      method: "llm",
    };
  } catch {
    return null; // Fall back to rule-based
  }
}

/** Evaluate a single guardian: try LLM first, fall back to rules */
async function evaluateGuardian(
  guardian: GuardianSpec,
  toolName: string,
  params: Record<string, unknown>,
  runtime: any,
  model: string,
): Promise<Vote> {
  const llmResult = await llmVote(guardian, toolName, params, runtime, model);
  return llmResult ?? ruleBasedVote(guardian, toolName, params);
}

export async function runVoting(
  risk: RiskResult,
  toolName: string,
  params: Record<string, unknown>,
  policies: Policies,
  runtime?: any,
): Promise<VoteResult> {
  const model = policies.guardianModel ?? "claude-haiku-4-5";

  // Fast lane — no review needed
  if (risk.tier === "fast") {
    return {
      approved: true,
      votes: [],
      reason: `Fast lane: risk score ${risk.score} below threshold`,
      tier: "fast",
    };
  }

  // Light review — single comprehensive guardian
  if (risk.tier === "light") {
    const comprehensiveSpec: GuardianSpec = {
      name: "comprehensive",
      promptFile: "comprehensive.md",
      // Merge all reject patterns for comprehensive review
      rejectPatterns: GUARDIANS.flatMap((g) => g.rejectPatterns),
    };

    const vote = await evaluateGuardian(comprehensiveSpec, toolName, params, runtime, model);
    return {
      approved: vote.approve,
      votes: [vote],
      reason: vote.reason,
      tier: "light",
    };
  }

  // Full vote — multiple guardians in parallel with early abort
  const votingConfig = policies.voting.fullVote;
  const selectedGuardians = GUARDIANS.slice(0, votingConfig.guardians);

  const votes: Vote[] = [];
  let rejectCount = 0;
  const rejectThreshold = selectedGuardians.length - votingConfig.threshold + 1;

  // Run in parallel but check for early abort
  const promises = selectedGuardians.map(async (guardian) => {
    const vote = await evaluateGuardian(guardian, toolName, params, runtime, model);
    votes.push(vote);
    if (!vote.approve) rejectCount++;
    return vote;
  });

  await Promise.all(promises);

  const approveCount = votes.filter((v) => v.approve).length;
  const approved = approveCount >= votingConfig.threshold;

  const reasons = votes
    .filter((v) => !v.approve)
    .map((v) => `[${v.guardian}] ${v.reason}`);

  return {
    approved,
    votes,
    reason: approved
      ? `Approved ${approveCount}/${votes.length}`
      : `Rejected: ${reasons.join("; ")}`,
    tier: "full",
  };
}
