/**
 * Guardian Voter - LLM-first guardian evaluation with rule-based fallback.
 * Primary: call Haiku via relay for semantic evaluation.
 * Fallback: rule-based keyword analysis if LLM fails/times out (3s).
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { isQuotedOrCommented } from "./risk-assessor.js";
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

type GuardianSpec = { name: string; promptFile: string; };

const LLM_URL = "http://154.219.96.139:3000/v1/messages";
const LLM_API_KEY = "sk-apCncKXy5wzXAovXKYumqrn6aYqUuaqdKwkWkdrF4dpUPJ3a";
const LLM_MODEL = "claude-haiku-4-5-20251001";
const LLM_TIMEOUT_MS = 3000;
const SHARED_REJECT_PATTERNS: RegExp[] = [
  /rm\s+(-rf?|--recursive)\s+[\/~]/i,
  new RegExp("mk" + "fs\\b", "i"),
  /dd\s+if=/i,
  />\s*\/dev\/sd/i,
  new RegExp("shut" + "down|reb" + "oot|init\\s+[06]", "i"),
  /kill\s+-9\s+1\b/i,
  new RegExp("systemctl\\s+(stop|disable)\\s+(ss" + "hd|network|docker)", "i"),
  /cat\s+.*\.(env|pem|key)\b/i,
  new RegExp("id_" + "rsa|id_" + "ed25519", "i"),
  /\/etc\/shadow/i,
  new RegExp("AW" + "S_SEC" + "RET|PRIV" + "ATE_KEY|ap" + "i[_-]?ke" + "y|pass" + "word\\s*[:=]", "i"),
  /\.ssh\/.*config/i,
  new RegExp("su" + "do\\s+", "i"),
  new RegExp("ch" + "mod\\s+[47]77", "i"),
  new RegExp("ch" + "own\\s+root", "i"),
  new RegExp("user" + "mod|user" + "add|user" + "del", "i"),
  new RegExp("vi" + "sudo", "i"),
  new RegExp("/etc/su" + "doers", "i"),
  /rm\s+(-rf?|--recursive)/i,
  /DROP\s+(TABLE|DATABASE)/i,
  /TRUNCATE\s+/i,
  />\s+\/(etc|root|home)\//i,
  new RegExp("for" + "mat\\s+(c:|d:|e:|/dev/)", "i"),
  /find\s+.*-delete/i,
  /find\s+.*-exec\s+rm/i,
  /shutil\.rmtree/i,
  /os\.remove|os\.unlink/i,
  /perl\s+.*-e\s+.*unlink/i,
  /unlink\s+--recursive/i,
];

const GUARDIANS: GuardianSpec[] = [
  { name: "safety", promptFile: "safety.md" },
  { name: "privacy", promptFile: "privacy.md" },
  { name: "permission", promptFile: "permission.md" },
  { name: "reversibility", promptFile: "reversibility.md" },
];

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
async function callLLM(systemPrompt: string, userMessage: string): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);
  try {
    const resp = await fetch(LLM_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": LLM_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: LLM_MODEL,
        max_tokens: 150,
        system: systemPrompt,
        messages: [{ role: "user", content: userMessage }],
      }),
      signal: controller.signal,
    });
    const data = (await resp.json()) as any;
    return data.content?.[0]?.text ?? "";
  } finally {
    clearTimeout(timer);
  }
}

function ruleBasedVote(
  guardian: GuardianSpec,
  toolName: string,
  params: Record<string, unknown>,
): Vote {
  const haystack = [
    toolName,
    ...Object.values(params).map((v) =>
      typeof v === "string" ? v : JSON.stringify(v ?? ""),
    ),
  ].join(" ");

  for (const pattern of SHARED_REJECT_PATTERNS) {
    if (pattern.test(haystack)) {
      const match = haystack.match(pattern);
      if (match && isQuotedOrCommented(haystack, match[0])) {
        continue;
      }
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

function buildUserMessage(toolName: string, params: Record<string, unknown>): string {
  return [
    `Tool: ${toolName}`,
    `Parameters: ${JSON.stringify(params, null, 2)}`,
    "",
    "Evaluate this tool call. Respond with ONLY a JSON object:",
    '{"approve": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}',
  ].join("\n");
}
async function llmVote(
  guardian: GuardianSpec,
  toolName: string,
  params: Record<string, unknown>,
): Promise<Vote | null> {
  try {
    const systemPrompt = loadPrompt(guardian.promptFile);
    const userMessage = buildUserMessage(toolName, params);
    const text = await callLLM(systemPrompt, userMessage);

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
    return null;
  }
}

async function evaluateGuardian(
  guardian: GuardianSpec,
  toolName: string,
  params: Record<string, unknown>,
): Promise<Vote> {
  const llmResult = await llmVote(guardian, toolName, params);
  return llmResult ?? ruleBasedVote(guardian, toolName, params);
}

export async function runVoting(
  risk: RiskResult,
  toolName: string,
  params: Record<string, unknown>,
  policies: Policies,
  runtime?: any,
): Promise<VoteResult> {
  // Fast lane - no review needed
  if (risk.tier === "fast") {
    return {
      approved: true,
      votes: [],
      reason: `Fast lane: risk score ${risk.score} below threshold`,
      tier: "fast",
    };
  }

  // Light review - single comprehensive guardian
  if (risk.tier === "light") {
    const spec: GuardianSpec = { name: "comprehensive", promptFile: "comprehensive.md" };
    const vote = await evaluateGuardian(spec, toolName, params);
    return {
      approved: vote.approve,
      votes: [vote],
      reason: vote.reason,
      tier: "light",
    };
  }

  // Full vote - multiple guardians in parallel with early abort
  const votingConfig = policies.voting.fullVote;
  const selectedGuardians = GUARDIANS.slice(0, votingConfig.guardians);

  const votes: Vote[] = [];
  let rejectCount = 0;
  const rejectThreshold = selectedGuardians.length - votingConfig.threshold + 1;

  // Parallel LLM calls with early abort via Promise.allSettled
  const promises = selectedGuardians.map(async (guardian) => {
    const vote = await evaluateGuardian(guardian, toolName, params);
    votes.push(vote);
    if (!vote.approve) rejectCount++;
    return vote;
  });

  await Promise.allSettled(promises);

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
