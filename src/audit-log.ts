/**
 * Audit Log — SHA-256 hash-chain append-only audit trail.
 * Each entry links to the previous via prevHash, forming a tamper-evident chain.
 * Writes to ~/.openclaw/guardian-audit.jsonl
 */

import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import type { RiskResult } from "./risk-assessor.js";
import type { Vote } from "./guardian-voter.js";

export type AuditEntry = {
  timestamp: string;
  toolName: string;
  params: Record<string, unknown>;
  riskScore: number;
  tier: string;
  matchedKeywords: string[];
  votes: Vote[];
  approved: boolean;
  reason: string;
  hash: string;
  prevHash: string;
};

let lastHash = "";
let logPath = "";

function getLogPath(customPath?: string): string {
  if (logPath) return logPath;
  logPath = customPath ?? join(homedir(), ".openclaw", "guardian-audit.jsonl");
  return logPath;
}

function computeHash(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Read the last hash from the existing log file (for chain continuity across restarts) */
function recoverLastHash(path: string): string {
  try {
    if (!existsSync(path)) return "";
    const content = readFileSync(path, "utf-8").trim();
    if (!content) return "";
    const lines = content.split("\n");
    const lastLine = lines[lines.length - 1];
    const entry = JSON.parse(lastLine) as AuditEntry;
    return entry.hash ?? "";
  } catch {
    return "";
  }
}

/** Initialize the audit log (call once at plugin startup) */
export function initAuditLog(customPath?: string): void {
  const path = getLogPath(customPath);
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  lastHash = recoverLastHash(path);
}

/** Append an audit entry to the log */
export function writeAuditEntry(
  toolName: string,
  params: Record<string, unknown>,
  risk: RiskResult,
  votes: Vote[],
  approved: boolean,
  reason: string,
): AuditEntry {
  const entry: Omit<AuditEntry, "hash"> & { hash?: string } = {
    timestamp: new Date().toISOString(),
    toolName,
    params: sanitizeParams(params),
    riskScore: risk.score,
    tier: risk.tier,
    matchedKeywords: risk.matchedKeywords,
    votes,
    approved,
    reason,
    prevHash: lastHash,
  };

  // Compute hash over the entry content (excluding hash field itself)
  const hashInput = JSON.stringify(entry);
  entry.hash = computeHash(hashInput);
  lastHash = entry.hash;

  const path = getLogPath();
  try {
    appendFileSync(path, JSON.stringify(entry) + "\n", "utf-8");
  } catch (err) {
    // Silently fail — audit should never block tool execution
    console.error(`[guardian] audit write failed: ${err}`);
  }

  return entry as AuditEntry;
}

/** Redact potentially sensitive values in params for the audit log */
function sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  const sensitiveKeys = /password|secret|token|key|credential|auth/i;

  for (const [k, v] of Object.entries(params)) {
    if (sensitiveKeys.test(k)) {
      sanitized[k] = "[REDACTED]";
    } else if (typeof v === "string" && v.length > 500) {
      sanitized[k] = v.slice(0, 500) + `... [truncated ${v.length} chars]`;
    } else {
      sanitized[k] = v;
    }
  }
  return sanitized;
}

/** Verify the integrity of the audit chain */
export function verifyAuditChain(customPath?: string): {
  valid: boolean;
  entries: number;
  brokenAt?: number;
} {
  const path = customPath ?? getLogPath();
  try {
    const content = readFileSync(path, "utf-8").trim();
    if (!content) return { valid: true, entries: 0 };

    const lines = content.split("\n");
    let prevHash = "";

    for (let i = 0; i < lines.length; i++) {
      const entry = JSON.parse(lines[i]) as AuditEntry;
      if (entry.prevHash !== prevHash) {
        return { valid: false, entries: lines.length, brokenAt: i };
      }

      // Recompute hash
      const { hash: storedHash, ...rest } = entry;
      const expectedHash = computeHash(JSON.stringify({ ...rest, prevHash: entry.prevHash }));
      if (storedHash !== expectedHash) {
        return { valid: false, entries: lines.length, brokenAt: i };
      }

      prevHash = storedHash;
    }

    return { valid: true, entries: lines.length };
  } catch {
    return { valid: false, entries: 0 };
  }
}
