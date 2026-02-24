/**
 * Blacklist rules — pure pattern matching, no LLM involved.
 * Two levels: "critical" (needs 3/3 LLM votes) and "warning" (needs 1/1).
 *
 * IMPORTANT: These patterns are checked against:
 *   - exec: the command string
 *   - write/edit: the file path
 * The caller (index.ts) decides what text to pass in.
 */

export type BlacklistMatch = {
  level: "critical" | "warning";
  pattern: string;
  reason: string;
};

interface Rule {
  pattern: RegExp;
  reason: string;
}

// ── CRITICAL: irreversible destruction or system compromise ────────
// Needs 3/3 LLM votes confirming user intent to pass

const CRITICAL_EXEC: Rule[] = [
  // Filesystem destruction — only recursive rm on system paths
  { pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|--recursive\s+)\/(?!tmp\/|home\/clawdbot\/)/, reason: "rm -rf on root-level system path" },
  { pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+|--recursive\s+)~\//, reason: "rm -rf on home directory" },
  { pattern: /mkfs\b/, reason: "filesystem format (mkfs)" },
  { pattern: /dd\s+if=.*of=\/dev\//, reason: "raw disk write (dd)" },
  { pattern: />\s*\/dev\/sd/, reason: "redirect to block device" },
  // System auth files (write/modify, not read)
  { pattern: /(?:tee|>>?)\s*\/etc\/(?:passwd|shadow|sudoers)/, reason: "write to system auth file" },
  { pattern: /sed\s+-i.*\/etc\/(?:passwd|shadow|sudoers)/, reason: "in-place edit of system auth file" },
  // System shutdown
  { pattern: /\b(?:shutdown|reboot)\b/, reason: "system shutdown/reboot" },
  { pattern: /\binit\s+[06]\b/, reason: "system halt/reboot (init)" },
  // Kill SSH (locks out remote access)
  { pattern: /systemctl\s+(?:stop|disable)\s+sshd/, reason: "disable SSH (remote lockout)" },
];

const CRITICAL_PATH: Rule[] = [
  { pattern: /^\/etc\/(?:passwd|shadow|sudoers)$/, reason: "write to system auth file" },
  { pattern: /^\/boot\//, reason: "write to boot partition" },
];

// ── WARNING: risky but possibly intentional ────────────────────────
// Needs 1/1 LLM vote confirming user intent to pass

const WARNING_EXEC: Rule[] = [
  // Recursive delete (non-system paths — CRITICAL already catches system paths)
  // Only match rm with BOTH -r (recursive) and force flags, not just -f alone
  { pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*)\s+/, reason: "recursive file deletion" },
  // Privilege escalation
  { pattern: /\bsudo\s+/, reason: "privilege escalation (sudo)" },
  // Dangerous permissions
  { pattern: /chmod\s+[47]77\b/, reason: "world-writable permission (chmod 777)" },
  // Force kill
  { pattern: /kill\s+-9\s+/, reason: "force kill process (SIGKILL)" },
  { pattern: /\bkillall\s+/, reason: "killall processes" },
  // Service management
  { pattern: /systemctl\s+(?:stop|disable|restart)\s+/, reason: "systemctl service operation" },
  // Database destruction
  { pattern: /DROP\s+(?:DATABASE|TABLE)\b/i, reason: "DROP DATABASE/TABLE" },
  { pattern: /TRUNCATE\s+/i, reason: "TRUNCATE table" },
];

const WARNING_PATH: Rule[] = [
  { pattern: /^\/etc\//, reason: "write to /etc/ system config" },
  { pattern: /^\/root\//, reason: "write to /root/ directory" },
];

// ── Safe Command Patterns (whitelist, checked before blacklist) ─────

const SAFE_EXEC: RegExp[] = [
  // git rm --cached only removes from index, not filesystem
  /^git\s+rm\s+.*--cached/,
  // git operations are generally safe
  /^git\s+(?:add|commit|push|pull|fetch|log|status|diff|branch|checkout|merge|rebase|stash|tag|remote|clone)\b/,
  // echo/printf just prints text
  /^(?:echo|printf)\s+/,
  // read-only commands
  /^(?:cat|head|tail|less|more|grep|find|ls|stat|file|wc|du|df|which|whereis|type|id|whoami|hostname|uname|date|uptime)\s*/,
  // package info (not install)
  /^(?:apt|dpkg|pip|npm)\s+(?:list|show|info|search)\b/,
];

// ── Quote/Comment Detection ────────────────────────────────────────

function isQuotedOrCommented(text: string, matchIndex: number): boolean {
  const before = text.slice(0, matchIndex);

  // Inside double quotes?
  const doubleQuotes = (before.match(/"/g) || []).length;
  if (doubleQuotes % 2 === 1) return true;

  // Inside single quotes?
  const singleQuotes = (before.match(/'/g) || []).length;
  if (singleQuotes % 2 === 1) return true;

  // After a comment character on the same line?
  const lastNewline = before.lastIndexOf("\n");
  const currentLine = before.slice(lastNewline + 1);
  if (currentLine.includes("#")) return true;

  return false;
}

// ── Matching ───────────────────────────────────────────────────────

function matchRules(text: string, rules: Rule[], level: "critical" | "warning"): BlacklistMatch | null {
  for (const rule of rules) {
    const m = rule.pattern.exec(text);
    if (m && !isQuotedOrCommented(text, m.index)) {
      return { level, pattern: rule.pattern.source, reason: rule.reason };
    }
  }
  return null;
}

// ── Command Segmentation ───────────────────────────────────────────

function splitCommand(cmd: string): string[] {
  // Split on shell operators, but not inside quotes
  const segments: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (ch === "'" && !inDouble) { inSingle = !inSingle; current += ch; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; current += ch; continue; }
    if (!inSingle && !inDouble) {
      if (ch === ';' || ch === '|') {
        segments.push(current.trim());
        current = "";
        // Skip && and ||
        if ((ch === '&' || ch === '|') && cmd[i+1] === ch) i++;
        continue;
      }
      if (ch === '&' && cmd[i+1] === '&') {
        segments.push(current.trim());
        current = "";
        i++;
        continue;
      }
    }
    current += ch;
  }
  if (current.trim()) segments.push(current.trim());
  return segments.filter(Boolean);
}

// ── Public API ─────────────────────────────────────────────────────

/**
 * Check a command (exec) against blacklist.
 * Splits on shell operators and checks each segment.
 * Returns null if no match (99% of calls).
 */
export function checkExecBlacklist(command: string): BlacklistMatch | null {
  if (!command) return null;
  const segments = splitCommand(command);
  for (const seg of segments) {
    // Whitelist check: safe commands skip blacklist entirely
    if (SAFE_EXEC.some(re => re.test(seg))) continue;

    const m = matchRules(seg, CRITICAL_EXEC, "critical")
      ?? matchRules(seg, WARNING_EXEC, "warning");
    if (m) return m;
  }
  return null;
}

/**
 * Check a file path (write/edit) against blacklist.
 * Returns null if no match.
 */
export function checkPathBlacklist(filePath: string): BlacklistMatch | null {
  if (!filePath) return null;
  return matchRules(filePath, CRITICAL_PATH, "critical")
    ?? matchRules(filePath, WARNING_PATH, "warning");
}
