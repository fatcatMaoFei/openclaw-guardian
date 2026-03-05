import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { parse } from "node:url";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import httpProxy from "http-proxy";
import { writeProxyAuditEntry, initAuditLog } from "./audit-log.js";
import dotenv from "dotenv";

dotenv.config();

const PROXY_PORT = parseInt(process.env.PROXY_PORT || "18790", 10);
const TARGET_URL = "http://127.0.0.1:18789";

// Load or generate token
const tokenPath = join(homedir(), ".openclaw", ".guardian_token");
let _token = process.env.GUARDIAN_TOKEN;

if (!_token) {
    if (existsSync(tokenPath)) {
        _token = readFileSync(tokenPath, "utf-8").trim();
    } else {
        _token = randomBytes(16).toString("hex"); // 32 chars
        writeFileSync(tokenPath, _token, "utf-8");
    }
}

export const GUARDIAN_TOKEN = _token!;

const proxy = httpProxy.createProxyServer({
    target: TARGET_URL,
    ws: true,
});

proxy.on("error", (err, req, res: any) => {
    console.error("[Proxy Error]", err);
    if (res && res.writeHead) {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Bad Gateway" }));
    }
});

function validateRequest(req: IncomingMessage, isWs: boolean): { ok: boolean; reason?: string } {
    const origin = req.headers.origin;
    if (origin && origin !== "http://localhost" && origin !== "http://127.0.0.1" && origin !== "null") {
        return { ok: false, reason: "Invalid Origin" };
    }

    const purl = parse(req.url || "", true);
    let token = purl.query.token as string;

    if (!token && req.headers.authorization) {
        const parts = req.headers.authorization.split(" ");
        if (parts.length === 2 && parts[0].toLowerCase() === "bearer") {
            token = parts[1];
        }
    }

    if (!token) {
        return { ok: false, reason: "Missing token" };
    }

    if (token !== GUARDIAN_TOKEN) {
        return { ok: false, reason: "Invalid token" };
    }

    return { ok: true };
}

export function startProxy(): void {
    initAuditLog();

    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
        const ip = req.socket.remoteAddress || "unknown";
        const { ok, reason } = validateRequest(req, false);

        if (!ok) {
            writeProxyAuditEntry(ip, "REJECTED", reason || "Unauthorized");
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: reason }));
            return;
        }

        writeProxyAuditEntry(ip, "PASSED", "Authorized");
        proxy.web(req, res);
    });

    server.on("upgrade", (req: IncomingMessage, socket: any, head: any) => {
        const ip = req.socket.remoteAddress || "unknown";
        const { ok, reason } = validateRequest(req, true);

        if (!ok) {
            writeProxyAuditEntry(ip, "REJECTED", reason || "Unauthorized WebSocket");
            socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
            socket.destroy();
            return;
        }

        writeProxyAuditEntry(ip, "PASSED", "Authorized WebSocket");
        proxy.ws(req, socket, head);
    });

    server.listen(PROXY_PORT, () => {
        console.log(`\n======================================================`);
        console.log(`🛡️  openclaw-guardian: Entry Protection is ONLINE 🛡️`);
        console.log(`======================================================`);
        console.log(`\nAll clients MUST connect to the proxy port: ws://localhost:${PROXY_PORT}`);
        console.log(`Access Token: ${GUARDIAN_TOKEN}`);
        console.log(`\nExample WebSocket connection:`);
        console.log(`  wscat -c ws://localhost:${PROXY_PORT}?token=${GUARDIAN_TOKEN}`);
        console.log(`\nExample HTTP webhook:`);
        console.log(`  http://localhost:${PROXY_PORT}/your-path?token=${GUARDIAN_TOKEN}`);
        console.log(`\nDo NOT connect directly to the gateway port 18789.`);
        console.log(`======================================================\n`);
    });
}
