# openclaw-guardian

A tiered safety layer for [OpenClaw](https://github.com/openclaw/openclaw).

Guardian intercepts tool calls before execution, assesses risk via keyword rules, and routes high-risk operations through Guardian voting — bringing layered safety to AI agent operations.

## How It Works

```
Model outputs tool_call
        ↓
  [before_tool_call hook]
        ↓
  Risk Assessor (keyword rules) scores 0-100
        ↓
  ┌─────────────────────────────────────────┐
  │ 0-30   → Fast Lane (pass through)      │
  │ 31-70  → Light Review (1 Guardian)     │
  │ 71-100 → Full Vote (3 Guardians)       │
  └─────────────────────────────────────────┘
        ↓
  Pass → Execute  |  Reject → Block + Reason
```

## Key Features

- **Tiered Risk Assessment**: Only high-risk operations trigger full Guardian review
- **Multi-Perspective Voting**: Each Guardian evaluates from a different angle (safety, privacy, permission, reversibility)
- **User-Configurable Policies**: Define per-tool base scores and keyword triggers in `default-policies.json`
- **Zero Core Changes**: Runs as a standard OpenClaw plugin via `before_tool_call` / `after_tool_call` hooks
- **Hash-Chain Audit Log**: Every decision logged with SHA-256 chain to `~/.openclaw/guardian-audit.jsonl`
- **Trust Budget**: Consecutive approvals auto-downgrade review tier for smoother flow
- **LLM-Optional**: Works fully with rule-based evaluation; optionally uses LLM via plugin runtime if available

## Architecture

```
openclaw-guardian/
├── openclaw.plugin.json    # Plugin manifest
├── index.ts                # Entry — registers hooks
├── src/
│   ├── risk-assessor.ts    # Keyword rule engine (0ms scoring)
│   ├── guardian-voter.ts   # Multi-guardian voting (rule + optional LLM)
│   └── audit-log.ts        # SHA-256 hash-chain audit trail
├── guardians/              # Guardian prompt templates
│   ├── safety.md           # Destructiveness review
│   ├── privacy.md          # Data leak review
│   ├── permission.md       # Scope/authority review
│   ├── reversibility.md    # Irreversibility review
│   └── comprehensive.md    # All-in-one (light review mode)
└── default-policies.json   # Default risk policies
```

## Installation

### Option 1: Local plugin (recommended)

```bash
# Clone or copy to your workspace
cp -r openclaw-guardian /path/to/your/workspace/

# Add to OpenClaw config (openclaw.json)
# Under plugins.load.paths:
{
  "plugins": {
    "load": {
      "paths": ["./openclaw-guardian"]
    },
    "entries": {
      "openclaw-guardian": {
        "config": {
          "enabled": true
        }
      }
    }
  }
}
```

### Option 2: Install via CLI

```bash
openclaw plugins install ./openclaw-guardian
openclaw gateway restart
```

## Configuration

### Plugin config (in openclaw.json)

```json
{
  "plugins": {
    "entries": {
      "openclaw-guardian": {
        "config": {
          "enabled": true,
          "policyPath": "./my-policies.json",
          "auditLogPath": "/tmp/guardian-audit.jsonl"
        }
      }
    }
  }
}
```

### Policy file (default-policies.json)

Each tool has a `baseScore` and optional `keywords` that add to the score:

```json
{
  "tool": "exec",
  "baseScore": 50,
  "keywords": {
    "rm -rf": 40,
    "sudo ": 25,
    "kill ": 20
  }
}
```

Score thresholds determine the review tier:
- `0–30` → Fast lane (no review)
- `31–70` → Light review (1 comprehensive guardian)
- `71–100` → Full vote (3 specialized guardians, majority required)

## Guardian Perspectives

| Guardian | Focus |
|----------|-------|
| Safety | Destructive operations, system damage, service disruption |
| Privacy | Credential exposure, PII leaks, secret access |
| Permission | Privilege escalation, scope violations |
| Reversibility | Irreversible actions, blast radius |
| Comprehensive | All angles combined (used in light review) |

## Audit Log

Every tool call decision is recorded in `~/.openclaw/guardian-audit.jsonl`:

```json
{
  "timestamp": "2026-02-24T09:30:00.000Z",
  "toolName": "exec",
  "params": { "command": "rm -rf /tmp/old" },
  "riskScore": 90,
  "tier": "full",
  "matchedKeywords": ["rm -rf"],
  "votes": [
    { "guardian": "safety", "approve": false, "reason": "..." }
  ],
  "approved": false,
  "reason": "Rejected: [safety] Rule match: rm\\s+(-rf?|--recursive)\\s+[\\/~]",
  "hash": "a1b2c3...",
  "prevHash": "d4e5f6..."
}
```

Verify chain integrity:

```typescript
import { verifyAuditChain } from "./src/audit-log.js";
const result = verifyAuditChain();
// { valid: true, entries: 142 }
```

## Trust Budget

When `trustBudget.enabled` is true, after N consecutive approvals (`autoDowngradeAfter`), the review tier is automatically downgraded:
- Full → Light
- Light → Fast

This reduces friction for well-behaved sessions. Any rejection resets the counter.

## License

MIT
