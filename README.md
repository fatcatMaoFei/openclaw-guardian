# openclaw-guardian

> **The missing safety layer for AI agents.**

## Why This Exists

OpenClaw is powerful — it gives AI agents direct access to shell commands, file operations, email, browser automation, and more. That power is exactly what makes it useful, but it's also what makes people nervous.

The community has been vocal: *"security nightmare"*, *"what if the AI deletes my files?"*, *"I don't trust it with my credentials"*. OpenClaw's existing safety (sandbox + allowlist + manual confirmation) only covers `exec`, and it's all-or-nothing — either you trust the agent completely, or you block everything.

**openclaw-guardian** fills that gap. It sits between the AI's decision and the actual execution, using a two-tier blacklist to catch dangerous operations and LLM-based intent verification to confirm the user actually asked for them. Think of it as a security checkpoint that only stops you when you're carrying something dangerous — and even then, it just checks your ID before letting you through.

> [!WARNING]
> **本插件强制启用入口防护，所有客户端必须连接 `ws://localhost:18790?token=xxx`，否则无法使用 OpenClaw！**
> 
> 基于最新的安全考量（如防范网页/JS 恶意连接），现在必须通过带有 token 校验的代理网关访问。

The key insight: **99% of what an AI agent does is harmless** (reading files, fetching URLs, writing notes). Only ~1% is potentially dangerous (deleting files, running destructive commands, accessing secrets). Guardian only intervenes on that 1%, so you get safety without sacrificing speed.

## How It Works

```
                          ┌──────────────────────────────────┐
  Client (Browser,        │  Layer 1: Entry Protection       │
  Telegram, Slack, etc.)  │  Guardian Proxy :18790           │
          │               │  ✓ Token 校验 (?token=xxx)       │
          │               │  ✓ Origin 校验 (localhost only)  │
          │               │  ✓ Every attempt → audit log     │
          ▼               └────────────┬─────────────────────┘
    ws://localhost:18790               │ token OK
    ?token=xxx                         ▼
                          ┌──────────────────────────────────┐
                          │  OpenClaw Gateway :18789         │
                          │  (bind loopback, 不直接暴露)     │
                          └────────────┬─────────────────────┘
                                       │ tool call
                                       ▼
                          ┌──────────────────────────────────┐
                          │  Layer 2: Execution Protection   │
                          │  ✓ Blacklist regex (0ms)         │
                          │  ✓ Sensitive data scan           │
                          │  ✓ LLM intent verification      │
                          └────────────┬─────────────────────┘
                                       │
                      ┌────────────────┼────────────────┐
                      ↓                ↓                ↓
                   No match         warning          critical
                   (pass)        (1 LLM vote)     (3 LLM votes)
                      ↓                ↓                ↓
                   Execute       1 vote check    3 parallel votes
                    0ms           ~1-2s            ~2-4s
                                       ↓                ↓
                                 confirmed? →    ALL 3 confirmed?
                                 yes: execute    yes: execute
                                 no: block       no: block
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

### Triple Protection Protocol (三重防护)

Guardian provides **three layers** of protection that work together:

**Layer 1 — Entry Protection (入口防护):** All clients must connect through the Guardian Proxy (port 18790) with a valid token. Malicious scripts, rogue webpages, or external attackers **cannot** directly reach the OpenClaw gateway on port 18789. This blocks the entire class of "ClawJacked" attacks where external JS silently connects to `ws://localhost:18789`.

**Layer 2 — Execution Protection (执行防护):** Regex blacklist + sensitive data scanning + LLM intent verification. Every tool call is checked before execution. Dangerous operations are blocked and logged.

**Layer 3 — Agent Self-Discipline (Agent 自律):** When an agent receives a Guardian block notification, it **must immediately stop**, report the blocked command and reason to the human user, and **wait for explicit confirmation** before proceeding.

**The protection chain:**

```
Client → Token 校验 (Layer 1) → Gateway → Tool call → Regex + Scan (Layer 2) → LLM 投票 → Agent 停下 (Layer 3) → 人类确认
```

**Why forced entry protection?** Without it, any webpage you visit could silently open `ws://localhost:18789` and send commands to your AI agent. The proxy acts as a door guard — no token, no entry. It's like putting a lock on your front door instead of just hoping nobody walks in.

#### Recommended AGENTS.md Rule

To activate Layer 3, add this rule to your `AGENTS.md` (or equivalent agent instructions file):

```markdown
### Guardian 三重防护协议（硬规则）
1. **第一层（入口防护）**：所有连接必须通过 Guardian Proxy (18790) + token 校验，恶意 JS/外部攻击者无法直连 gateway
2. **第二层（执行防护）**：regex 初筛 + 敏感数据扫描 + LLM 意图确认，自动拦截危险操作
3. **第三层（Agent 自律）**：当 Guardian 拦截命令时，agent 收到拦截通知后**必须立刻停下**，向用户报告被拦截的命令和原因，等待确认后才能继续。禁止自行绕过、重试或换方式执行被拦截的操作。
4. **防护链**：token 校验 → regex 初筛 → 敏感数据扫描 → LLM 投票 → Guardian 拦截 → agent 停下 → 人类确认 → 继续/放弃
```

This ensures the agent treats Guardian blocks as hard stops rather than soft suggestions.

### Why Not Just Use LLMs for Everything?

Guardian's blacklist uses **zero-cost keyword rules** — no model calls for pattern matching. Regex like `rm -rf /` → critical, `sudo` → warning is instant and deterministic. LLM verification is only triggered for the ~1% of operations that actually hit the blacklist, and its only job is confirming user intent — not scoring risk.

## Quick Start

### Step 1: Clone & Install

```bash
cd ~/.openclaw/workspace
git clone https://github.com/fatcatMaoFei/openclaw-guardian.git
cd openclaw-guardian
npm install
```

### Step 2: Register Plugin (执行防护)

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

Then restart the gateway:

```bash
openclaw gateway restart
```

> This activates **Layer 2 (Execution Protection)** — blacklist + sensitive data scan + LLM voting on every tool call.

### Step 3: Start Guardian Proxy (入口防护)

```bash
npm run start
```

Console output will display:

```
======================================================
🛡️  openclaw-guardian: Entry Protection is ONLINE 🛡️
======================================================

All clients MUST connect to the proxy port: ws://localhost:18790
Access Token: a1b2c3d4e5f6...your_32_char_token...

Example WebSocket connection:
  wscat -c ws://localhost:18790?token=a1b2c3d4...

Example HTTP webhook:
  http://localhost:18790/your-path?token=a1b2c3d4...

Do NOT connect directly to the gateway port 18789.
======================================================
```

> This activates **Layer 1 (Entry Protection)** — all connections must carry a valid token.

### Step 4: Update All Client Connections

**All clients must now use the Guardian proxy port `18790` and supply the token:**

| Client Type | Before | After |
|-------------|--------|-------|
| WebSocket | `ws://localhost:18789` | `ws://localhost:18790?token=YOUR_TOKEN` |
| HTTP webhook | `http://localhost:18789/path` | `http://localhost:18790/path?token=YOUR_TOKEN` |
| Telegram | webhook → `:18789/tg` | webhook → `:18790/tg?token=YOUR_TOKEN` |
| Slack | webhook → `:18789/slack` | webhook → `:18790/slack?token=YOUR_TOKEN` |

Alternatively, pass the token in the HTTP header:
```
Authorization: Bearer YOUR_TOKEN
```

> [!CAUTION]
> **Do NOT connect directly to port 18789.** The entire point of this plugin is that all traffic must pass through the proxy's token validation layer.

### Step 5: Verify It Works

```bash
# Should FAIL (no token):
wscat -c ws://localhost:18790
# → Connection rejected: 401 Unauthorized

# Should SUCCEED (with token):
wscat -c "ws://localhost:18790?token=YOUR_TOKEN"
# → Connected to OpenClaw gateway
```

## Customization

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

All events are logged to `~/.openclaw/guardian-audit.jsonl`. There are two types of log entries:

**Proxy connection log (Layer 1):**
```json
{
  "timestamp": "2026-03-05T09:30:00.000Z",
  "event": "PROXY_CONNECTION",
  "ip": "::1",
  "status": "REJECTED",
  "reason": "Missing token"
}
```

**Tool call interception log (Layer 2, with SHA-256 hash chain):**
```json
{
  "timestamp": "2026-03-05T09:30:00.000Z",
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

Tamper-evident: each tool call entry's hash includes the previous entry's hash. Break one link and the whole chain fails verification.

## Configuration

### Environment Variables (`.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `18790` | Port for the Guardian Proxy |
| `GUARDIAN_TOKEN` | (auto-generated) | Token for client authentication. If not set, auto-generates a 32-char hex token and saves to `~/.openclaw/.guardian_token` |

Create a `.env` file in the project root to customize:

```env
PROXY_PORT=18790
GUARDIAN_TOKEN=your_custom_token_here
```

### Enable / Disable Execution Protection

Edit `default-policies.json`:

```json
{
  "enabled": true
}
```

Set to `false` to disable Guardian's execution protection (blacklist + LLM) entirely without uninstalling. The proxy (entry protection) runs independently.

## Architecture

```
openclaw-guardian/
├── openclaw.plugin.json    # Plugin manifest (v2.0.0)
├── index.ts                # Plugin entry — before_tool_call hook + sensitive scan
├── src/
│   ├── proxy-server.ts     # 🆕 Entry protection — token-gated reverse proxy (:18790 → :18789)
│   ├── start.ts            # 🆕 Standalone entry point (npm run start)
│   ├── sensitive-scan.ts   # 🆕 Regex scanner for API keys, tokens, passwords in tool params
│   ├── blacklist.ts        # Two-tier keyword rules (critical/warning) + reverse shells, container escapes
│   ├── llm-voter.ts        # LLM intent verification (single vote or 3-vote unanimous)
│   └── audit-log.ts        # SHA-256 hash-chain audit logger + proxy connection logger
├── default-policies.json   # Enable/disable execution protection toggle
├── package.json
└── tsconfig.json
```

### How It Hooks Into OpenClaw

**Entry Protection (proxy-server.ts):** Runs as a standalone HTTP/WebSocket reverse proxy. Listens on port 18790, validates token + Origin on every connection, and forwards valid traffic to the OpenClaw gateway on port 18789.

**Execution Protection (index.ts):** Registers a `before_tool_call` plugin hook in OpenClaw's agent loop (`Model → tool_call → Tool Executor → result → Model`). This hook fires **after** the model decides to call a tool but **before** the tool actually executes. If Guardian returns `{ block: true }`, the tool is stopped and the model receives a rejection message.

The two layers are independent — the proxy runs as a separate process, while the plugin runs inside OpenClaw. Both write to the same audit log at `~/.openclaw/guardian-audit.jsonl`.

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
