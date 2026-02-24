/**
 * OpenClaw Guardian — Plugin Entry Point
 *
 * Registers before_tool_call and after_tool_call hooks to intercept tool
 * execution, assess risk, and optionally run guardian voting before allowing
 * high-risk operations to proceed.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { assessRisk, type Policies } from "./src/risk-assessor.js";
import { runVoting } from "./src/guardian-voter.js";
import { initAuditLog, writeAuditEntry } from "./src/audit-log.js";

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";

type GuardianPluginConfig = {
  enabled?: boolean;
  policyPath?: string;
  auditLogPath?: string;
};

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadPolicies(customPath?: string): Policies {
  const path = customPath ?? join(__dirname, "default-policies.json");
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as Policies;
  } catch (err) {
    console.error(`[guardian] Failed to load policies from ${path}, using defaults`);
    return {
      enabled: true,
      thresholds: { low: 30, high: 70 },
      guardianModel: "claude-haiku-4-5",
      policies: [],
      voting: {
        lightReview: { guardians: 1, threshold: 1 },
        fullVote: { guardians: 3, threshold: 2 },
      },
      trustBudget: { enabled: true, autoDowngradeAfter: 10 },
    };
  }
}

/** Trust budget: track consecutive approvals to auto-downgrade review level */
const trustState = {
  consecutiveApprovals: 0,
};

export default function setup(api: OpenClawPluginApi): void {
  const pluginCfg = (api.pluginConfig ?? {}) as GuardianPluginConfig;

  // Master switch
  if (pluginCfg.enabled === false) {
    api.logger.info("[guardian] Plugin disabled via config");
    return;
  }

  const policies = loadPolicies(pluginCfg.policyPath);
  if (!policies.enabled) {
    api.logger.info("[guardian] Policies disabled");
    return;
  }

  // Initialize audit log
  initAuditLog(pluginCfg.auditLogPath);
  api.logger.info("[guardian] Initialized — safety gate active");

  // ── before_tool_call ─────────────────────────────────────────────
  api.on("before_tool_call", async (event, ctx) => {
    const { toolName, params } = event;

    // Assess risk
    const risk = assessRisk(toolName, params, policies);

    // Apply trust budget: downgrade tier if many consecutive approvals
    let effectiveRisk = risk;
    if (
      policies.trustBudget.enabled &&
      trustState.consecutiveApprovals >= policies.trustBudget.autoDowngradeAfter
    ) {
      if (risk.tier === "full") {
        effectiveRisk = { ...risk, tier: "light" };
      } else if (risk.tier === "light") {
        effectiveRisk = { ...risk, tier: "fast" };
      }
    }

    // Fast lane — skip voting entirely
    if (effectiveRisk.tier === "fast") {
      // Still log for audit trail
      writeAuditEntry(toolName, params, risk, [], true, "Fast lane");
      return; // pass through
    }

    // Run guardian voting
    const result = await runVoting(effectiveRisk, toolName, params, policies, api.runtime);

    // Update trust budget
    if (result.approved) {
      trustState.consecutiveApprovals++;
    } else {
      trustState.consecutiveApprovals = 0;
    }

    // Write audit entry
    writeAuditEntry(toolName, params, risk, result.votes, result.approved, result.reason);

    if (!result.approved) {
      api.logger.warn(
        `[guardian] BLOCKED ${toolName} — score: ${risk.score}, reason: ${result.reason}`,
      );
      return {
        block: true,
        blockReason: `🛡️ Guardian blocked: ${result.reason} (risk: ${risk.score}/100)`,
      };
    }

    api.logger.info(
      `[guardian] APPROVED ${toolName} — score: ${risk.score}, tier: ${effectiveRisk.tier}, votes: ${result.votes.length}`,
    );
    return; // pass through
  });

  // ── after_tool_call ──────────────────────────────────────────────
  api.on("after_tool_call", async (event, _ctx) => {
    // Log errors for post-hoc analysis
    if (event.error) {
      api.logger.warn(
        `[guardian] Tool ${event.toolName} failed after ${event.durationMs ?? "?"}ms: ${event.error}`,
      );
    }
  });
}
