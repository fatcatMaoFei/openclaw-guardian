# openclaw-guardian

> **The missing safety layer for AI agents.**

## Why This Exists

OpenClaw gives AI agents direct access to shell commands, file operations, browser automation, and more. That power is what makes it useful — and what makes people nervous.

**openclaw-guardian** sits between the AI's decision and actual execution, intercepting dangerous operations via a two-tier blacklist and routing them through independent LLM voters for intent verification. Safe operations pass through with zero overhead.

The key insight: **99% of tool calls are harmless.** Guardian only intervenes on the ~1% that match known dangerous patterns — so you get safety without sacrificing speed.

## Architecture (v2)

```
Tool call arrives (before_tool_call hook)
              ↓
    Is it exec / write / edit?
      no → pass through (0ms)
      yes ↓
    Blacklist pattern match?
      no → pass through (0ms, 99% of calls end here)
      yes ↓
  ┌─────────────────────────────────┐
  │  critical        │  warning     │
  │  3 LLM votes     │  1 LLM vote  │
  │  ALL must confirm │              │
  └────────┬─────────┴──────┬───────┘
           ↓                ↓
     3/3 pass → allow   confirmed → allow
     any fail → BLOCK   denied → BLOCK
```

### Two-Tier Blacklist

| Level | LLM Votes | Threshold | Examples |
|-------|-----------|-----------|---------|
| **critical** | 3 (parallel) | All 3 must confirm user intent | `rm -rf /`, `mkfs`, `dd of=/dev/`, write to `/etc/shadow`, pipe to shell |
| **warning** | 1 | Must confirm user intent | `sudo`, `chmod 777`, `kill -9`, recursive delete on non-system paths |

No match → instant pass-through. No scoring, no model calls, zero latency.

### What Gets Checked

Only three tool types are inspected:

| Tool | Checked Against |
|------|----------------|
| `exec` | Command string matched against exec blacklist patterns |
| `write` | File path matched against path blacklist patterns |
| `edit` | File path matched against path blacklist patterns |

Everything else (`read`, `web_fetch`, `browser`, etc.) passes instantly.

### LLM Intent Verification

When a blacklist pattern matches, Guardian doesn't just block — it asks a lightweight LLM: *"Did the user actually request this?"*

- Uses the cheapest available model from your existing OpenClaw provider config (prefers Haiku / GPT-4o-mini / Gemini Flash)
- Reads recent conversation context to verify user intent
- No separate API key needed
- 5-second timeout; if LLM is unavailable: critical → block, warning → block with user prompt

### SHA-256 Audit Log

Every blacklist-matched operation is logged to `~/.openclaw/guardian-audit.jsonl` as a hash-chained append-only trail:

```jsonc
{
  "timestamp": "2026-02-26T01:00:00.000Z",
  "toolName": "exec",
  "blacklistLevel": "critical",
  "blacklistReason": "rm -rf on root-level system path",
  "pattern": "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*)\\s+\\/(?!\\/tmp\\/)",
  "userConfirmed": false,
  "finalReason": "Only 1/3 confirmed (need 3)",
  "prevHash": "a1b2c3...",
  "hash": "d4e5f6..."  // SHA-256(entry + prevHash)
}
```

Each entry's `hash` covers the full entry plus `prevHash`, forming a tamper-evident chain.

## Quick Start

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
      "openclaw-guardian": {
        "enabled": true
      }
    }
  }
}
```

### 3. Done

Guardian activates on next OpenClaw restart. No extra API keys, no config files to edit — it uses your existing model providers.

## Bypass Prevention

Guardian includes patterns to catch common evasion techniques:

- Absolute path to binaries (`/bin/rm -rf`)
- Interpreter-based execution (`python3 -c`, `node -e`, `perl -e`)
- Pipe to shell (`curl ... | bash`, `base64 -d | sh`)
- Indirect deletion (`xargs rm`, `find -exec rm`, `find -delete`)
- `eval` execution

Safe commands (`ls`, `cat`, `echo`, `git status`, `pwd`, etc.) are whitelisted and skip blacklist checks entirely.

## Project Structure

```
openclaw-guardian/
├── index.ts                # Entry — registers before_tool_call hook
├── src/
│   ├── blacklist.ts        # Two-tier pattern matching (critical / warning)
│   ├── llm-voter.ts        # LLM intent verification (single + multi vote)
│   └── audit-log.ts        # SHA-256 hash-chain audit logger
├── openclaw.plugin.json    # Plugin manifest
├── default-policies.json   # Enable/disable toggle
└── package.json
```

## Cost

| Scenario | % of Calls | Extra Cost |
|----------|-----------|------------|
| No blacklist match | ~99% | 0 (pattern match only) |
| Warning match | ~0.8% | ~500 tokens (1 LLM call) |
| Critical match | ~0.2% | ~1500 tokens (3 parallel LLM calls) |

Most operations cost nothing extra.

## License

MIT
