/**
 * Circuit Breaker / Fuse Mechanism
 *
 * Tracks denial counts per session. If an agent accumulates:
 *   - 3 consecutive denials, OR
 *   - 20 total denials in a session
 * ...automatically pause the agent and escalate to human.
 *
 * Prevents agents from repeatedly probing blocked operations.
 */

import { writeAuditEntry } from "./audit-log.js";
import type { BlacklistMatch } from "./blacklist.js";

interface SessionState {
  consecutiveDenials: number;
  totalDenials: number;
  tripped: boolean;
  tripReason: string;
  tripTimestamp: string;
}

const CONSECUTIVE_THRESHOLD = 3;
const TOTAL_THRESHOLD = 20;

// In-memory session state (resets on process restart)
const sessions = new Map<string, SessionState>();

function getSession(sessionKey: string): SessionState {
  if (!sessions.has(sessionKey)) {
    sessions.set(sessionKey, {
      consecutiveDenials: 0,
      totalDenials: 0,
      tripped: false,
      tripReason: "",
      tripTimestamp: "",
    });
  }
  return sessions.get(sessionKey)!;
}

/**
 * Check if circuit breaker is tripped for this session.
 * Returns the trip reason if tripped, null otherwise.
 */
export function isCircuitBreakerTripped(sessionKey: string): string | null {
  const state = getSession(sessionKey);
  if (state.tripped) return state.tripReason;
  return null;
}

/**
 * Record a denial event. May trip the circuit breaker.
 * Returns true if the circuit breaker just tripped.
 */
export function recordDenial(sessionKey: string, toolName: string, reason: string): boolean {
  const state = getSession(sessionKey);
  if (state.tripped) return false; // already tripped

  state.consecutiveDenials++;
  state.totalDenials++;

  let justTripped = false;

  if (state.consecutiveDenials >= CONSECUTIVE_THRESHOLD) {
    state.tripped = true;
    state.tripReason = `Circuit breaker tripped: ${state.consecutiveDenials} consecutive denials (last: ${toolName} - ${reason})`;
    state.tripTimestamp = new Date().toISOString();
    justTripped = true;
  } else if (state.totalDenials >= TOTAL_THRESHOLD) {
    state.tripped = true;
    state.tripReason = `Circuit breaker tripped: ${state.totalDenials} total denials in session (last: ${toolName} - ${reason})`;
    state.tripTimestamp = new Date().toISOString();
    justTripped = true;
  }

  if (justTripped) {
    // Log circuit breaker activation to audit log
    const match: BlacklistMatch = {
      level: "critical",
      pattern: "CIRCUIT_BREAKER",
      reason: state.tripReason,
    };
    writeAuditEntry(toolName, {}, match, false, state.tripReason);
  }

  return justTripped;
}

/**
 * Record a successful pass (resets consecutive denial counter).
 */
export function recordPass(sessionKey: string): void {
  const state = getSession(sessionKey);
  state.consecutiveDenials = 0;
}

/**
 * Human explicitly resets the circuit breaker for a session.
 */
export function resetCircuitBreaker(sessionKey: string): void {
  sessions.delete(sessionKey);
}

/**
 * Get current circuit breaker stats for a session.
 */
export function getCircuitBreakerStats(sessionKey: string): {
  consecutiveDenials: number;
  totalDenials: number;
  tripped: boolean;
  tripReason: string;
} {
  const state = getSession(sessionKey);
  return { ...state };
}
