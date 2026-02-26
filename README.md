# openclaw-guardian

> **The missing safety layer for AI agents.**

## Why This Exists

OpenClaw is powerful — it gives AI agents direct access to shell commands, file operations, email, browser automation, and more. That power is exactly what makes it useful, but it's also what makes people nervous.

The community has been vocal: *"security nightmare"*, *"what if the AI deletes my files?"*, *"I don't trust it with my credentials"*. OpenClaw's existing safety (sandbox + allowlist + manual confirmation) only covers `exec`, and it's all-or-nothing — either you trust the agent completely, or you block everything.

**openclaw-guardian** fills that gap. It sits between the AI's decision and the actual execution, using a two-tier blacklist to catch dangerous operations and LLM-based intent verification to confirm the user actually asked for them. Think of it as a security checkpoint that only stops you when you're carrying something dangerous — and even then, it just checks your ID before letting you through.

The key insight: **99% of what an AI agent does is harmless** (reading files, fetching URLs, writing notes). Only ~1% is potentially dangerous (deleting files, running destructive commands, accessing secrets). Guardian only intervenes on that 1%, so you get safety without sacrificing speed.

## How It Works

```
AI Agent wants to run a tool (e.g., exec "rm -rf /tmp/data")
                    ↓
        ┌───────────────────────┐
        │   Blacklist Matcher   │  ← Keyword rules, 0ms, no model call
        │   critical / warning  │
        └───────────┬───────────┘
                    ↓
    ┌───────────────┼───────────────┐
    ↓               ↓               ↓
 No match        warning          critical
 (just go)     (1 LLM vote)    (3 LLM votes)
    ↓               ↓               ↓
 Execute       1 vote check     3 parallel votes
  0ms          ~1-2s            ~2-4s
                    ↓               ↓
              confirmed? →     ALL 3 confirmed?
              yes: execute     yes: execute
              no: block        no: block
```

### Two-Tier Blacklist

| Tier | LLM Votes | Threshold | Latency | When |
|------|-----------|-----------|---------|------|
| No match | 0 | — | 0ms | Reading files, fetching URLs, normal operations |
| Warning | 1 | 1/1 | ~1-2s | `sudo`, `rm -r`, `chmod 777`, writing to `.env` |
| Critical | 3 | 3/3 | ~2-4s | `rm -rf /`, `mkfs`, `dd of=/dev/`, writing to `/etc/passwd` |

### What Gets Flagged

**Critical** (irreversible destruction or system compromise — needs 3/3 unanimous LLM confirmation):

| Pattern | Why |
|---------|-----|
| `rm -rf` on system paths | Filesystem destruction |
| `mkfs`, `dd of=/dev/` | Disk-level destruction |
| Write to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | System auth compromise |
| `shutdown`, `reboot` | System availability |
| `curl \| bash`, `base64 -d \| sh` | Remote code execution |
| `xargs rm`, `find -delete` | Indirect bulk deletion |

**Warning** (risky but possibly intentional — needs 1/1 LLM confirmation):

| Pattern | Why |
|---------|-----|
| `sudo` | Privilege escalation |
| `rm -r` (non-system paths) | Recursive deletion |
| `chmod 777`, `chmod -R`, `chown -R` | Dangerous permissions |
| `kill -9`, `killall`, `pkill` | Force kill processes |
| `systemctl stop/disable` | Service disruption |
| `eval` | Arbitrary code execution (review before running) |
| Write to `.env`, `.ssh/`, `openclaw.json` | Sensitive file modification |

### LLM Intent Verification

When a blacklist rule matches, Guardian doesn't just block — it reads the recent conversation context and asks a lightweight LLM: **"Did the user explicitly request this operation?"**

- Uses the cheapest/fastest model available from your existing OpenClaw config (prefers Haiku, GPT-4o-mini, Gemini Flash)
- No separate API key needed — piggybacks on whatever you already have configured
- If LLM is unavailable: critical → block (fail-safe), warning → ask user

### Whitelist (Always Allowed)

These commands are considered safe and will never be flagged, even if they appear inside a broader command:

| Pattern | Why |
|---------|-----|
| `mkdir` | Creating directories is non-destructive |
| `touch` | Creating empty files is non-destructive |
| `tar`, `unzip`, `gzip`, `gunzip`, `bzip2`, `xz` | Archive extraction/compression — normal dev workflow |
| `openclaw` (CLI) | OpenClaw's own CLI commands (e.g., `openclaw gateway status`) |

Whitelist rules are checked **before** the blacklist. If a command matches a whitelist pattern, it passes through immediately with zero overhead.

### Tool-Level Blacklist

Guardian doesn't just inspect `exec`, `write`, and `edit` — it also scans tool calls for **any** tool (e.g., `message`, `browser`, database clients, email plugins). To avoid false positives on normal payloads, it only checks action-oriented fields: `action`, `method`, `command`, and `operation` — not the entire parameter object.

**Critical** (3/3 unanimous LLM confirmation):

| Pattern | Why |
|---------|-----|
| `batchDelete`, `expunge`, `emptyTrash`, `purge` | Bulk email deletion — irreversible mailbox destruction |
| `DROP DATABASE`, `DROP TABLE`, `TRUNCATE`, `DELETE FROM` | Database destruction — irreversible data loss |

**Warning** (1/1 LLM confirmation):

| Pattern | Why |
|---------|-----|
| `delete`, `trash` | Single-item deletion — usually intentional but worth confirming |

Everyday operations like `send`, `get`, `web_fetch`, `cron`, `snapshot`, etc. are completely unaffected — they never match any blacklist pattern.

### Dual Protection Protocol (双重防护)

Guardian provides two layers of protection that work together:

**Layer 1 — Guardian Plugin (automatic):** Regex pattern matching + LLM intent verification. When a dangerous operation is detected, Guardian blocks the tool call and returns a rejection message to the agent.

**Layer 2 — Agent Self-Discipline (behavioral):** When an agent receives a Guardian block notification, it **must immediately stop**, report the blocked command and reason to the human user, and **wait for explicit confirmation** before proceeding. The agent must not attempt to bypass, retry, or find alternative ways to execute the blocked operation.

**The protection chain:**

```
Tool call → Regex match → Guardian blocks → Agent stops → Reports to human → Human decides → Continue or abort
```

This dual approach ensures that even if an agent is determined to perform a dangerous action, it cannot silently retry or work around the block. The human always stays in the loop for any operation Guardian considers risky.

#### Recommended AGENTS.md Rule

To activate Layer 2, add this rule to your `AGENTS.md` (or equivalent agent instructions file):

```markdown
### Guardian 双重防护协议（硬规则）
1. **第一层（Guardian 插件）**：regex 初筛 + LLM 意图确认，自动拦截危险操作
2. **第二层（Agent 自觉）**：当 Guardian 拦截命令时，agent 收到拦截通知后**必须立刻停下**，向用户报告被拦截的命令和原因，等待确认后才能继续。禁止自行绕过、重试或换方式执行被拦截的操作。
3. **防护链**：regex 初筛 → Guardian 拦截 → agent 停下 → 人类确认 → 继续/放弃
```

This ensures the agent treats Guardian blocks as hard stops rather than soft suggestions.

### Why Not Just Use LLMs for Everything?

Guardian's blacklist uses **zero-cost keyword rules** — no model calls for pattern matching. Regex like `rm -rf /` → critical, `sudo` → warning is instant and deterministic. LLM verification is only triggered for the ~1% of operations that actually hit the blacklist, and its only job is confirming user intent — not scoring risk.

## Quick Start (One Command)

### 1. Clone into your OpenClaw workspace

```bash
cd ~/.openclaw/workspace
git clone https://github.com/fatcatMaoFei/openclaw-guardian.git
```

### 2. Register the plugin

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "load": {
      "paths": ["./openclaw-guardian"]
    },
    "entries": {
      "openclaw-guardian": {
        "enabled": true
      }
    }
  }
}
```

### 3. Restart

```bash
openclaw gateway restart
```

That's it. Guardian is now active. Every tool call goes through blacklist checking automatically.

## Customization

### Enable / Disable

Edit `default-policies.json`:

```json
{
  "enabled": true
}
```

Set to `false` to disable Guardian entirely without uninstalling.

### Blacklist Rules

The blacklist is defined in `src/blacklist.ts` with two levels of rules:

- **`CRITICAL_EXEC` / `CRITICAL_PATH`** — patterns that trigger 3-vote unanimous LLM verification
- **`WARNING_EXEC` / `WARNING_PATH`** — patterns that trigger 1-vote LLM verification
- **`SAFE_EXEC`** — whitelisted commands that skip blacklist entirely (e.g., `ls`, `cat`, `git status`)

To add your own rules, add a regex + reason to the appropriate array. For example:

```typescript
// Add to WARNING_EXEC to flag any docker commands
{ pattern: /\bdocker\s+(?:rm|rmi|system\s+prune)\b/, reason: "docker resource removal" },
```

### LLM Model Selection

Guardian automatically picks the cheapest available model from your OpenClaw config. Preference order:

1. `claude-haiku-4-5` (Anthropic)
2. `gpt-4o-mini` (OpenAI)
3. `gemini-2.0-flash` (Google)
4. First available model (fallback)

No extra configuration needed.

## Audit Trail

Every blacklist-matched operation is logged to `~/.openclaw/guardian-audit.jsonl` with SHA-256 hash chaining:

```json
{
  "timestamp": "2026-02-24T09:30:00.000Z",
  "toolName": "exec",
  "blacklistLevel": "critical",
  "blacklistReason": "rm -rf on root-level system path",
  "pattern": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*\\s+|--recursive\\s+)\\/",
  "userConfirmed": false,
  "finalReason": "Only 1/3 confirmed (need 3)",
  "hash": "a1b2c3...",
  "prevHash": "d4e5f6..."
}
```

Tamper-evident: each entry's hash includes the previous entry's hash. Break one link and the whole chain fails verification.

## Architecture

```
openclaw-guardian/
├── openclaw.plugin.json    # Plugin manifest (v2.0.0)
├── index.ts                # Entry — registers before_tool_call hook, routes blacklist hits to LLM
├── src/
│   ├── blacklist.ts        # Two-tier keyword rules (critical/warning), 0ms, no model calls
│   ├── llm-voter.ts        # LLM intent verification (single vote or 3-vote unanimous)
│   └── audit-log.ts        # SHA-256 hash-chain audit logger
├── default-policies.json   # Enable/disable toggle
├── package.json
└── tsconfig.json
```

### How It Hooks Into OpenClaw

OpenClaw's agent loop: `Model → tool_call → Tool Executor → result → Model`

Guardian registers a `before_tool_call` plugin hook. This hook fires **after** the model decides to call a tool but **before** the tool actually executes. If Guardian returns `{ block: true }`, the tool is stopped and the model receives a rejection message instead.

This is the same hook interface OpenClaw uses internally for loop detection — battle-tested, async-safe, and zero modifications to core code.

## Token Cost

| Tier | % of Operations | Extra Cost |
|------|----------------|------------|
| No match (pass) | ~99% | 0 (no model call) |
| Warning (1 vote) | ~0.5-1% | ~500 tokens per review |
| Critical (3 votes) | <0.5% | ~1500 tokens per review |

**Average overhead: near zero.** The vast majority of operations never hit the blacklist. When they do, Guardian uses the cheapest model available.

## Status

🚧 Under active development — contributions welcome.

## License

MIT
