import type { BlacklistMatch } from "./blacklist.js";

// Regexes for common sensitive data
const SENSITIVE_PATTERNS = [
    { regex: /sk-[a-zA-Z0-9]{48}/, reason: "OpenAI Secret Key" },
    { regex: /AKIA[0-9A-Z]{16}/, reason: "AWS Access Key ID" },
    { regex: /(?:bearer|authorization)\s*[:=]\s*(?:bearer\s+)?([a-zA-Z0-9-_\.]+)/i, reason: "Bearer/Authorization Token" },
    { regex: /password\s*=\s*['"]?([^'"\s&]+)/i, reason: "Plaintext Password" },
    { regex: /xox[baprs]-[0-9a-zA-Z]+/, reason: "Slack Token" },
    { regex: /gh[ps]_[a-zA-Z0-9]{36}/, reason: "GitHub Token" },
];

/**
 * Scans tool call parameters for sensitive data strings (credentials).
 * @param params Tool parameters to scan
 * @returns BlacklistMatch or null if safe
 */
export function scanSensitiveData(params: Record<string, unknown>): BlacklistMatch | null {
    const paramsStr = JSON.stringify(params);

    for (const pattern of SENSITIVE_PATTERNS) {
        if (pattern.regex.test(paramsStr)) {
            const match = paramsStr.match(pattern.regex);
            return {
                pattern: pattern.regex.toString(),
                level: "warning",
                reason: `Sensitive data exposure detected: ${pattern.reason}`,
            };
        }
    }

    return null;
}
