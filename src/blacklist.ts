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
  // === BYPASS PREVENTION ===
  // Absolute path to rm
  { pattern: /\/bin\/rm\s+(-[a-zA-Z]*r[a-zA-Z]*)\s+/, reason: "rm via absolute path" },
  { pattern: /\/usr\/bin\/rm\s+(-[a-zA-Z]*r[a-zA-Z]*)\s+/, reason: "rm via absolute path" },
  // (eval, perl -e, ruby -e moved to WARNING)
  // xargs with dangerous commands
  { pattern: /xargs\s+.*\brm\b/, reason: "xargs rm (indirect deletion)" },
  { pattern: /xargs\s+.*\bchmod\b/, reason: "xargs chmod (indirect permission change)" },
  // find -exec with dangerous commands
  { pattern: /find\s+.*-exec\s+.*\brm\b/, reason: "find -exec rm (indirect deletion)" },
  { pattern: /find\s+.*-delete\b/, reason: "find -delete (bulk deletion)" },
];

const CRITICAL_PATH: Rule[] = [
  { pattern: /^\/etc\/(?:passwd|shadow|sudoers)$/, reason: "write to system auth file" },
  { pattern: /^\/boot\//, reason: "write to boot partition" },
];

// ── WARNING: risky but possibly intentional ────────────────────────
// Needs 1/1 LLM vote confirming user intent to pass

const WARNING_EXEC: Rule[] = [
  // Recursive delete (non-system paths — CRITICAL already catches system paths)
  { pattern: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*)\s+/, reason: "recursive file deletion" },
  // Privilege escalation
  { pattern: /\bsudo\s+/, reason: "privilege escalation (sudo)" },
  // Dangerous permissions
  { pattern: /chmod\s+[47]77\b/, reason: "world-writable permission (chmod 777)" },
  { pattern: /chmod\s+-R\s+/, reason: "recursive permission change" },
  { pattern: /chown\s+-R\s+/, reason: "recursive ownership change" },
  // Force kill
  { pattern: /kill\s+-9\s+/, reason: "force kill process (SIGKILL)" },
  { pattern: /\bkillall\s+/, reason: "killall processes" },
  { pattern: /\bpkill\s+/, reason: "pkill processes" },
  // Service management (only stop/disable — restart is less dangerous)
  { pattern: /systemctl\s+(?:stop|disable)\s+/, reason: "systemctl stop/disable service" },
  // Database destruction
  { pattern: /DROP\s+(?:DATABASE|TABLE)\b/i, reason: "DROP DATABASE/TABLE" },
  { pattern: /TRUNCATE\s+/i, reason: "TRUNCATE table" },
  // Interpreter inline execution (only check eval — python/node/perl/ruby are normal dev tools)
  { pattern: /\beval\s+/, reason: "eval execution (arbitrary code)" },
  // Network/firewall changes
  { pattern: /\biptables\s+/, reason: "firewall rule change (iptables)" },
  { pattern: /\bufw\s+(?:allow|deny|delete|disable)\b/, reason: "firewall rule change (ufw)" },
  // Crontab modification
  { pattern: /\bcrontab\s+(-r|-e)\b/, reason: "crontab modification" },
  // Disk operations
  { pattern: /\bfdisk\s+/, reason: "disk partition operation" },
  { pattern: /\bparted\s+/, reason: "disk partition operation" },
  { pattern: /\bmount\s+/, reason: "filesystem mount operation" },
  { pattern: /\bumount\s+/, reason: "filesystem unmount operation" },
  // SSH key operations
  { pattern: /ssh-keygen\s+/, reason: "SSH key generation/modification" },
  // Environment variable manipulation that could affect security
  { pattern: /export\s+(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH)=/, reason: "security-sensitive environment variable change" },
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
  // echo/printf — ONLY safe if not piped to shell (pipe splits into separate segments)
  /^(?:echo|printf)\s+/,
  // read-only commands — exclude find (can be used with -exec/-delete)
  /^(?:cat|head|tail|less|more|grep|ls|stat|file|wc|du|df|which|whereis|type|id|whoami|hostname|uname|date|uptime)\s*/,
  // package info (not install)
  /^(?:apt|dpkg|pip|npm)\s+(?:list|show|info|search)\b/,
  // safe file operations (create only, no overwrite risk)
  /^(?:mkdir|touch)\s+/,
  // archive/compression (read-heavy, low risk)
  /^(?:tar|unzip|gzip|gunzip|bzip2|xz|7z)\s+/,
  // openclaw CLI
  /^openclaw\s+/,
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

/**
 * Like matchRules but skips quote/comment detection.
 * Used for interpreter payloads where quotes are language syntax, not shell quoting.
 */
function matchRulesRaw(text: string, rules: Rule[], level: "critical" | "warning"): BlacklistMatch | null {
  for (const rule of rules) {
    const m = rule.pattern.exec(text);
    if (m) {
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
      // Check double-char operators first: && and ||
      if ((ch === '&' && cmd[i + 1] === '&') || (ch === '|' && cmd[i + 1] === '|')) {
        segments.push(current.trim());
        current = "";
        i++; // skip second char
        continue;
      }
      // Single-char separators: ; | \n
      if (ch === ';' || ch === '|' || ch === '\n') {
        segments.push(current.trim());
        current = "";
        continue;
      }
    }
    current += ch;
  }
  if (current.trim()) segments.push(current.trim());
  return segments.filter(Boolean);
}

// ── Shell Wrapper Extraction ───────────────────────────────────────

/**
 * Extract payload from shell wrapper commands like:
 *   bash -c "rm -rf /tmp/test"
 *   sh -lc 'dangerous command'
 *   bash -c 'cmd1 && cmd2'
 * Returns the inner payload string, or null if not a wrapper.
 */
function extractShellWrapperPayload(command: string): string | null {
  // Match: bash|sh|zsh|dash [-flags]c "payload" or 'payload'
  const wrapperMatch = command.match(
    /^\s*(?:\/(?:usr\/)?bin\/)?(?:bash|sh|zsh|dash)\s+(?:-[a-zA-Z]*c|-c)\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+))/
  );
  if (wrapperMatch) {
    return wrapperMatch[1] ?? wrapperMatch[2] ?? wrapperMatch[3] ?? null;
  }
  return null;
}

/**
 * Extract inline code from interpreter commands:
 *   python -c "import os; os.system('rm -rf /')"
 *   python3 -c "..."
 *   node -e "..."
 *   perl -e "..."
 *   ruby -e "..."
 */
function extractInterpreterPayload(command: string): string | null {
  const interpMatch = command.match(
    /^\s*(?:python[23]?|node|perl|ruby)\s+(?:-[a-zA-Z]*[ce]|-[ce])\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)')/
  );
  if (interpMatch) {
    return interpMatch[1] ?? interpMatch[2] ?? null;
  }
  return null;
}

// ── Public API ─────────────────────────────────────────────────────

/**
 * Check a command (exec) against blacklist.
 * Splits on shell operators and checks each segment.
 * Returns null if no match (99% of calls).
 */
export function checkExecBlacklist(command: string): BlacklistMatch | null {
  if (!command) return null;

  // Phase 1: Check the FULL command string for pipe-based attacks
  // These patterns span across pipe boundaries and must be checked before splitting
  const PIPE_ATTACKS: Rule[] = [
    { pattern: /base64\s+(-d|--decode).*\|\s*(?:bash|sh|zsh|dash)/, reason: "base64 decoded pipe to shell" },
    { pattern: /\bcurl\b.*\|\s*(?:bash|sh|zsh|dash|python|perl|ruby)/, reason: "curl pipe to shell (remote code execution)" },
    { pattern: /\bwget\b.*\|\s*(?:bash|sh|zsh|dash|python|perl|ruby)/, reason: "wget pipe to shell (remote code execution)" },
    { pattern: /\becho\b.*\|\s*(?:bash|sh|zsh|dash)\b/, reason: "echo pipe to shell" },
    { pattern: /\bprintf\b.*\|\s*(?:bash|sh|zsh|dash)\b/, reason: "printf pipe to shell" },
    { pattern: /\|\s*(?:bash|sh|zsh|dash)\s*$/, reason: "pipe to shell interpreter" },
    { pattern: /\|\s*(?:bash|sh|zsh|dash)\s*[;&|]/, reason: "pipe to shell interpreter" },
  ];
  const fullMatch = matchRules(command, PIPE_ATTACKS, "critical");
  if (fullMatch) return fullMatch;

  // Phase 2: Unwrap shell wrappers (bash -c, sh -lc, etc.)
  // This prevents bypass via: bash -c "rm -rf /important"
  const segments = splitCommand(command);
  for (const seg of segments) {
    // Check for shell wrapper bypass
    const shellPayload = extractShellWrapperPayload(seg);
    if (shellPayload) {
      // Recursively check the inner payload
      const innerMatch = checkExecBlacklist(shellPayload);
      if (innerMatch) {
        return {
          ...innerMatch,
          reason: `${innerMatch.reason} (via shell wrapper: ${seg.slice(0, 40)}...)`,
        };
      }
    }

    // Check for interpreter inline code
    const interpPayload = extractInterpreterPayload(seg);
    if (interpPayload) {
      // Check interpreter payload against exec blacklist patterns
      // Use matchRulesRaw: quotes inside interpreter code are language syntax, not shell quoting
      const innerMatch = matchRulesRaw(interpPayload, CRITICAL_EXEC, "critical")
        ?? matchRulesRaw(interpPayload, WARNING_EXEC, "warning");
      if (innerMatch) {
        return {
          ...innerMatch,
          reason: `${innerMatch.reason} (via interpreter inline code)`,
        };
      }
    }
  }

  // Phase 3: Split on shell operators and check each segment
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

// ── Tool-level blacklist (catches dangerous actions regardless of implementation) ──

interface ToolRule {
  tool: RegExp;
  param: string;
  pattern: RegExp;
  level: "critical" | "warning";
  reason: string;
}

const TOOL_RULES: ToolRule[] = [
  // Email: bulk delete / trash / expunge (irreversible)
  { tool: /.*/, param: "*", pattern: /\b(?:batchDelete|expunge|emptyTrash|purge)\b/i, level: "critical", reason: "bulk email deletion (irreversible)" },
  // Email: single delete/trash (only matches action field value)
  { tool: /.*/, param: "*", pattern: /\b(?:delete|trash)\b/i, level: "warning", reason: "email/message deletion" },
  // Destructive database queries embedded in tool params
  { tool: /.*/, param: "*", pattern: /\b(?:DROP\s+(?:DATABASE|TABLE)|TRUNCATE\s+|DELETE\s+FROM)\b/i, level: "critical", reason: "destructive database query in tool params" },
];

/**
 * Check any tool call's params against tool-level blacklist.
 * Only checks specific param fields (not full serialization) to avoid false positives.
 * Skips exec/write/edit (already handled by dedicated checkers).
 * Returns null if no match.
 */
export function checkToolBlacklist(toolName: string, params: Record<string, unknown>): BlacklistMatch | null {
  // exec/write/edit already have dedicated checkers
  if (toolName === "exec" || toolName === "write" || toolName === "edit") return null;
  if (!params || Object.keys(params).length === 0) return null;

  // Only check action-like fields for all rules
  const actionFields = ["action", "method", "command", "operation"];
  const actionValue = actionFields
    .map(f => typeof params[f] === "string" ? params[f] as string : "")
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  for (const rule of TOOL_RULES) {
    if (!rule.tool.test(toolName)) continue;
    const m = rule.pattern.exec(actionValue);
    if (m) return { level: rule.level, pattern: rule.pattern.source, reason: rule.reason };
  }
  return null;
}
