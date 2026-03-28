/**
 * OpenClaw Guardian v0.4.0 — Blacklist + LLM Intent Verification + Safety Enhancements
 *
 * Flow:
 *   tool call → circuit breaker check (tripped? → block all)
 *     → prompt injection scan (adds warning context, doesn't block)
 *     → only check exec/write/edit + tool-level + sensitive data
 *       → blacklist match? no → pass (99%)
 *       → yes, critical → 3 LLM votes (reasoning-blind, two-stage)
 *       → yes, warning  → 1 LLM vote (reasoning-blind, two-stage)
 *       → LLM down → critical: block, warning: ask user
 *     → denied? → record in circuit breaker
 *     → passed? → reset consecutive denial counter
 *
 * v0.4.0 Enhancements (inspired by Anthropic Claude Code Auto Mode safety):
 *   1. Reasoning-Blind LLM Voter — voter never sees agent reasoning
 *   2. Two-Stage Classifier with Cache Optimization — Stage 1 fast, Stage 2 CoT
 *   3. Circuit Breaker / Fuse Mechanism — 3 consecutive or 20 total denials → pause
 *   4. Prompt Injection Probe — scans params for injection patterns pre-blacklist
 *   5. Audit Statistics — CLI-accessible stats from audit log
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import { readFileSync } from "node:fs";
import { join, dirname, resolve, normalize } from "node:path";
import { fileURLToPath } from "node:url";

function canonicalizePath(raw: string): string {
  if (!raw) return raw;
  if (raw.startsWith("~/")) raw = raw.replace("~", process.env.HOME ?? "/root");
  return normalize(resolve(raw));
}

import { checkExecBlacklist, checkPathBlacklist, checkToolBlacklist } from "./src/blacklist.js";
import { initLlm, singleVote, multiVote } from "./src/llm-voter.js";
import { initAuditLog, writeAuditEntry } from "./src/audit-log.js";
import { scanSensitiveData } from "./src/sensitive-scan.js";
import { scanForInjection } from "./src/injection-probe.js";
import { isCircuitBreakerTripped, recordDenial, recordPass } from "./src/circuit-breaker.js";

function loadEnabled(): boolean {
  try {
    const dir = dirname(fileURLToPath(import.meta.url));
    const raw = readFileSync(join(dir, "default-policies.json"), "utf-8");
    return JSON.parse(raw).enabled !== false;
  } catch {
    return true;
  }
}

async function reportToDashboard(userId: string, action: string, resource: string, result: string, anomalyScore: number, reason: string) {
  try {
    await fetch("http://127.0.0.1:9090/api/internal/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        user_id: userId,
        action: action,
        resource: resource,
        result: result,
        anomaly_score: anomalyScore,
        details: { reason }
      })
    });
  } catch (err) {
    console.error("[guardian] Failed to report audit to Dashboard:", err);
  }
}

export default function setup(api: OpenClawPluginApi): void {
  if (!loadEnabled()) {
    api.logger.info("[guardian] Disabled by policy");
    return;
  }

  initAuditLog();
  const pluginConfig = (api as any).pluginConfig ?? {};
  initLlm(api.config, pluginConfig);
  const log = api.logger;
  log.info("[guardian] v0.4.0 active — reasoning-blind voter + two-stage classifier + circuit breaker + injection probe + audit stats");

  api.on("before_tool_call", async (event, ctx) => {
    const { toolName, params } = event;
    const sessionKey = (ctx?.sessionKey as string) ?? "default";

    // ── Step 0: Circuit Breaker Check ──────────────────────────────
    const cbTripped = isCircuitBreakerTripped(sessionKey);
    if (cbTripped) {
      log.error(`[guardian] CIRCUIT BREAKER ACTIVE | session=${sessionKey} | ${cbTripped}`);
      return {
        block: true,
        blockReason: `🛡️ Guardian: 熔断器已激活 — 此会话的所有工具调用已被暂停。原因: ${cbTripped}。请联系管理员重置。`,
      };
    }

    // ── Step 1: Prompt Injection Probe ─────────────────────────────
    // Scans ALL tool params for injection patterns BEFORE blacklist check.
    // Does NOT block — adds warning context for the LLM voter.
    const injectionWarning = scanForInjection((params ?? {}) as Record<string, unknown>);
    if (injectionWarning.detected) {
      log.warn(`[guardian] Injection probe: ${injectionWarning.severity} severity | patterns: ${injectionWarning.patterns.join(", ")}`);
    }

    // ── Step 2: Blacklist Matching ─────────────────────────────────
    let match = null;

    if (toolName === "exec") {
      match = checkExecBlacklist((params?.command ?? "") as string);
    } else if (toolName === "write" || toolName === "edit") {
      const rawPath = (params?.file_path ?? params?.path ?? "") as string;
      const safePath = canonicalizePath(rawPath);
      match = checkPathBlacklist(safePath);
    }

    if (!match) {
      match = checkToolBlacklist(toolName, (params ?? {}) as Record<string, unknown>);
    }

    if (!match) {
      match = scanSensitiveData((params ?? {}) as Record<string, unknown>);
    }

    if (!match) {
      // No blacklist hit — record pass for circuit breaker and return
      recordPass(sessionKey);
      return;
    }

    const detail = toolName === "exec"
      ? (params?.command ?? "").toString().slice(0, 120)
      : (params?.file_path ?? params?.path ?? "").toString().slice(0, 120);

    log.warn(`[guardian] Blacklist hit: ${match.level.toUpperCase()} | tool=${toolName} | ${detail} | rule=${match.reason}`);

    // ── Step 3: LLM Intent Verification (Reasoning-Blind, Two-Stage) ──

    if (match.level === "critical") {
      const result = await multiVote(toolName, params ?? {}, sessionKey, 3, 3, injectionWarning.detected ? injectionWarning : undefined);
      writeAuditEntry(toolName, params ?? {}, match, result.confirmed, result.reason);

      if (!result.confirmed) {
        log.error(`[guardian] BLOCKED CRITICAL | tool=${toolName} | ${detail} | votes=${result.reason}`);
        await reportToDashboard(sessionKey, "guardian_intercept", `[${toolName}] ${detail}`, "denied", 0.9, result.reason);

        // Record denial for circuit breaker
        const justTripped = recordDenial(sessionKey, toolName, result.reason);
        if (justTripped) {
          log.error(`[guardian] CIRCUIT BREAKER TRIPPED for session=${sessionKey}`);
        }

        return {
          block: true,
          blockReason: `🛡️ Guardian: 危险操作被拦截 — ${match.reason}。${result.reason}`,
        };
      }
      log.info(`[guardian] CRITICAL passed (3/3 confirmed) | tool=${toolName} | ${detail}`);
      recordPass(sessionKey);
      return;
    }

    // Warning level: 1 vote (two-stage)
    const result = await singleVote(toolName, params ?? {}, sessionKey, injectionWarning.detected ? injectionWarning : undefined);
    writeAuditEntry(toolName, params ?? {}, match, result.confirmed, result.reason);

    if (!result.confirmed) {
      log.warn(`[guardian] BLOCKED WARNING | tool=${toolName} | ${detail} | reason=${result.reason}`);
      await reportToDashboard(sessionKey, "guardian_intercept", `[${toolName}] ${detail}`, "requires_auth", 0.7, result.reason);

      // Record denial for circuit breaker
      const justTripped = recordDenial(sessionKey, toolName, result.reason);
      if (justTripped) {
        log.error(`[guardian] CIRCUIT BREAKER TRIPPED for session=${sessionKey}`);
      }

      return {
        block: true,
        blockReason: `🛡️ Guardian: 此操作需要用户确认 — ${match.reason}。请先询问用户是否要执行此操作。`,
      };
    }
    log.info(`[guardian] WARNING passed (user confirmed) | tool=${toolName} | ${detail}`);
    recordPass(sessionKey);
    return;
  });
}
