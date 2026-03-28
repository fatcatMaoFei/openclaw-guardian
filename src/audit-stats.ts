/**
 * Audit Statistics
 *
 * Reads the audit log and computes:
 * - Total operations checked
 * - Block rate by tier (critical/warning)
 * - False positive estimate (blocks later manually approved)
 * - Top blocked patterns
 * - Simple stats summary for CLI
 */

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { AuditEntry } from "./audit-log.js";

interface AuditStats {
  totalEntries: number;
  toolCallEntries: number;
  proxyEntries: number;
  byTier: {
    critical: { total: number; blocked: number; confirmed: number; blockRate: string };
    warning: { total: number; blocked: number; confirmed: number; blockRate: string };
  };
  falsePositiveEstimate: {
    count: number;
    rate: string;
    description: string;
  };
  topBlockedPatterns: Array<{ reason: string; count: number }>;
  circuitBreakerActivations: number;
  injectionWarnings: number;
  timeRange: { earliest: string; latest: string };
}

function getLogPath(): string {
  return join(homedir(), ".openclaw", "guardian-audit.jsonl");
}

/**
 * Parse all entries from the audit log.
 */
function parseAuditLog(): Array<Record<string, any>> {
  const path = getLogPath();
  if (!existsSync(path)) return [];

  const content = readFileSync(path, "utf-8").trim();
  if (!content) return [];

  const entries: Array<Record<string, any>> = [];
  for (const line of content.split("\n")) {
    if (!line.trim()) continue;
    try {
      entries.push(JSON.parse(line));
    } catch { /* skip malformed */ }
  }
  return entries;
}

/**
 * Estimate false positives: operations that were blocked but then a very similar
 * operation was confirmed shortly after (within 5 minutes).
 * This suggests the user retried and confirmed, meaning the original block
 * was arguably a false positive.
 */
function estimateFalsePositives(toolEntries: Array<Record<string, any>>): { count: number; rate: string } {
  let falsePositiveCount = 0;
  const blocked = toolEntries.filter(e => !e.userConfirmed);
  const confirmed = toolEntries.filter(e => e.userConfirmed);

  for (const block of blocked) {
    const blockTime = new Date(block.timestamp).getTime();
    // Check if same tool + similar reason was confirmed within 5 min
    const wasRetried = confirmed.some(c => {
      const confirmTime = new Date(c.timestamp).getTime();
      return c.toolName === block.toolName
        && confirmTime > blockTime
        && confirmTime - blockTime < 5 * 60 * 1000;
    });
    if (wasRetried) falsePositiveCount++;
  }

  const rate = blocked.length > 0
    ? ((falsePositiveCount / blocked.length) * 100).toFixed(1) + "%"
    : "N/A";

  return { count: falsePositiveCount, rate };
}

/**
 * Compute audit statistics.
 */
export function computeAuditStats(): AuditStats {
  const allEntries = parseAuditLog();

  // Separate tool call entries from proxy entries
  const toolEntries = allEntries.filter(e => e.toolName !== undefined);
  const proxyEntries = allEntries.filter(e => e.event === "PROXY_CONNECTION");

  // By tier
  const critical = toolEntries.filter(e => e.blacklistLevel === "critical");
  const warning = toolEntries.filter(e => e.blacklistLevel === "warning");

  const critBlocked = critical.filter(e => !e.userConfirmed).length;
  const critConfirmed = critical.filter(e => e.userConfirmed).length;
  const warnBlocked = warning.filter(e => !e.userConfirmed).length;
  const warnConfirmed = warning.filter(e => e.userConfirmed).length;

  // Top blocked patterns
  const patternCounts = new Map<string, number>();
  for (const entry of toolEntries.filter(e => !e.userConfirmed)) {
    const reason = entry.blacklistReason || entry.finalReason || "unknown";
    patternCounts.set(reason, (patternCounts.get(reason) || 0) + 1);
  }
  const topPatterns = Array.from(patternCounts.entries())
    .map(([reason, count]) => ({ reason, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Circuit breaker activations
  const cbActivations = toolEntries.filter(e => e.pattern === "CIRCUIT_BREAKER").length;

  // Injection warnings (entries with injection context)
  const injectionWarnings = toolEntries.filter(e =>
    e.finalReason?.includes("injection") || e.blacklistReason?.includes("injection")
  ).length;

  // False positive estimate
  const fp = estimateFalsePositives(toolEntries);

  // Time range
  const timestamps = allEntries.map(e => e.timestamp).filter(Boolean).sort();

  return {
    totalEntries: allEntries.length,
    toolCallEntries: toolEntries.length,
    proxyEntries: proxyEntries.length,
    byTier: {
      critical: {
        total: critical.length,
        blocked: critBlocked,
        confirmed: critConfirmed,
        blockRate: critical.length > 0 ? ((critBlocked / critical.length) * 100).toFixed(1) + "%" : "N/A",
      },
      warning: {
        total: warning.length,
        blocked: warnBlocked,
        confirmed: warnConfirmed,
        blockRate: warning.length > 0 ? ((warnBlocked / warning.length) * 100).toFixed(1) + "%" : "N/A",
      },
    },
    falsePositiveEstimate: {
      count: fp.count,
      rate: fp.rate,
      description: "Blocks where the same tool was confirmed within 5 minutes (likely user retry)",
    },
    topBlockedPatterns: topPatterns,
    circuitBreakerActivations: cbActivations,
    injectionWarnings,
    timeRange: {
      earliest: timestamps[0] ?? "N/A",
      latest: timestamps[timestamps.length - 1] ?? "N/A",
    },
  };
}

/**
 * Generate a human-readable stats summary for CLI output.
 */
export function formatAuditStats(): string {
  const stats = computeAuditStats();
  const lines: string[] = [];

  lines.push("====================================================");
  lines.push("  OpenClaw Guardian -- Audit Statistics");
  lines.push("====================================================");
  lines.push("");
  lines.push(`  Period: ${stats.timeRange.earliest} -> ${stats.timeRange.latest}`);
  lines.push(`  Total audit entries: ${stats.totalEntries}`);
  lines.push(`    Tool call checks: ${stats.toolCallEntries}`);
  lines.push(`    Proxy connections: ${stats.proxyEntries}`);
  lines.push("");
  lines.push("  -- By Tier ------------------------------------------");
  lines.push(`  CRITICAL: ${stats.byTier.critical.total} checked | ${stats.byTier.critical.blocked} blocked | ${stats.byTier.critical.confirmed} confirmed | block rate: ${stats.byTier.critical.blockRate}`);
  lines.push(`  WARNING:  ${stats.byTier.warning.total} checked | ${stats.byTier.warning.blocked} blocked | ${stats.byTier.warning.confirmed} confirmed | block rate: ${stats.byTier.warning.blockRate}`);
  lines.push("");
  lines.push("  -- False Positive Estimate ---------------------------");
  lines.push(`  Estimated: ${stats.falsePositiveEstimate.count} (${stats.falsePositiveEstimate.rate})`);
  lines.push(`  Method: ${stats.falsePositiveEstimate.description}`);
  lines.push("");

  if (stats.circuitBreakerActivations > 0) {
    lines.push(`  Circuit breaker activations: ${stats.circuitBreakerActivations}`);
  }
  if (stats.injectionWarnings > 0) {
    lines.push(`  Injection warnings: ${stats.injectionWarnings}`);
  }

  if (stats.topBlockedPatterns.length > 0) {
    lines.push("");
    lines.push("  -- Top Blocked Patterns ------------------------------");
    for (const p of stats.topBlockedPatterns) {
      lines.push(`  ${String(p.count).padStart(4)} x ${p.reason}`);
    }
  }

  lines.push("");
  lines.push("====================================================");

  return lines.join("\n");
}

// CLI entry point
if (process.argv[1]?.endsWith("audit-stats.ts") || process.argv[1]?.endsWith("audit-stats.js")) {
  console.log(formatAuditStats());
}
