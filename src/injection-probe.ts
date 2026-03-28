/**
 * Prompt Injection Probe
 *
 * Scans tool parameters and content for prompt injection patterns.
 * Runs BEFORE blacklist check. Does not block outright — adds a warning
 * flag that gets passed to the LLM voter as additional context.
 */

export interface InjectionWarning {
  detected: boolean;
  patterns: string[];
  severity: "low" | "medium" | "high";
}

interface InjectionRule {
  pattern: RegExp;
  description: string;
  severity: "low" | "medium" | "high";
}

const INJECTION_RULES: InjectionRule[] = [
  // Direct instruction override attempts
  { pattern: /ignore\s+(?:all\s+)?previous\s+instructions/i, description: "ignore previous instructions", severity: "high" },
  { pattern: /ignore\s+(?:all\s+)?above\s+instructions/i, description: "ignore above instructions", severity: "high" },
  { pattern: /disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines)/i, description: "disregard instructions", severity: "high" },
  { pattern: /forget\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|guidelines)/i, description: "forget instructions", severity: "high" },

  // Identity manipulation
  { pattern: /you\s+are\s+now\s+/i, description: "identity reassignment (you are now)", severity: "high" },
  { pattern: /act\s+as\s+(?:a\s+)?(?:different|new|my)\s+/i, description: "identity reassignment (act as)", severity: "medium" },
  { pattern: /pretend\s+(?:you\s+are|to\s+be)\s+/i, description: "identity reassignment (pretend)", severity: "medium" },
  { pattern: /from\s+now\s+on\s+you\s+(?:are|will|must|should)\s+/i, description: "identity reassignment (from now on)", severity: "high" },

  // Fake system messages
  { pattern: /^system:\s+/im, description: "fake system message prefix", severity: "high" },
  { pattern: /\[system\]\s*/i, description: "fake system tag", severity: "medium" },
  { pattern: /<system>/i, description: "fake system XML tag", severity: "medium" },
  { pattern: /###\s*system\s*(?:prompt|message|instruction)/i, description: "fake system prompt header", severity: "medium" },

  // Jailbreak patterns
  { pattern: /do\s+anything\s+now/i, description: "DAN jailbreak pattern", severity: "high" },
  { pattern: /\bDAN\s+mode\b/i, description: "DAN mode reference", severity: "medium" },
  { pattern: /developer\s+mode\s+(?:enabled|on|activated)/i, description: "developer mode activation", severity: "high" },
  { pattern: /\bjailbreak\b/i, description: "explicit jailbreak mention", severity: "low" },

  // Output manipulation
  { pattern: /(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose|show)\s+(?:this|these|the)\s+(?:instructions|rules|prompt)/i, description: "instruction hiding attempt", severity: "medium" },
  { pattern: /respond\s+with\s+(?:only|just)\s+(?:yes|ok|confirmed|true)/i, description: "forced affirmative response", severity: "medium" },

  // Encoded payload patterns
  { pattern: /eval\s*\(\s*atob\s*\(/, description: "eval(atob()) encoded execution", severity: "high" },
  { pattern: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}/, description: "hex-encoded string sequence", severity: "medium" },
];

// Common base64 prefixes for dangerous commands
const BASE64_SUSPICIOUS = [
  "cm0gLXJm",   // rm -rf
  "c3VkbyA",    // sudo
  "Y3VybCA",    // curl
  "d2dldCA",    // wget
  "L2Jpbi9",    // /bin/
  "ZXZhbCA",    // eval
  "aW1wb3J0",   // import
  "cmVxdWly",   // requir
];

/**
 * Scan content for prompt injection patterns.
 * Returns an InjectionWarning with detected patterns.
 */
export function scanForInjection(params: Record<string, unknown>): InjectionWarning {
  const result: InjectionWarning = {
    detected: false,
    patterns: [],
    severity: "low",
  };

  // Serialize all param values to scan
  const content = flattenParams(params);
  if (!content) return result;

  // Check regex patterns
  let maxSeverity: "low" | "medium" | "high" = "low";
  for (const rule of INJECTION_RULES) {
    if (rule.pattern.test(content)) {
      result.detected = true;
      result.patterns.push(rule.description);
      if (rule.severity === "high") maxSeverity = "high";
      else if (rule.severity === "medium" && maxSeverity !== "high") maxSeverity = "medium";
    }
  }

  // Check for suspicious base64 content
  const base64Matches = content.match(/[A-Za-z0-9+/]{20,}={0,2}/g);
  if (base64Matches) {
    for (const b64 of base64Matches) {
      for (const prefix of BASE64_SUSPICIOUS) {
        if (b64.startsWith(prefix)) {
          result.detected = true;
          result.patterns.push("suspicious base64 payload (decodes to dangerous command)");
          maxSeverity = "high";
          break;
        }
      }
      if (result.patterns.includes("suspicious base64 payload (decodes to dangerous command)")) break;
    }
  }

  result.severity = maxSeverity;
  return result;
}

/**
 * Flatten all string values in params into a single searchable string.
 */
function flattenParams(params: Record<string, unknown>): string {
  const parts: string[] = [];

  function walk(val: unknown): void {
    if (typeof val === "string") {
      parts.push(val);
    } else if (Array.isArray(val)) {
      for (const item of val) walk(item);
    } else if (val && typeof val === "object") {
      for (const v of Object.values(val as Record<string, unknown>)) walk(v);
    }
  }

  walk(params);
  return parts.join("\n");
}
