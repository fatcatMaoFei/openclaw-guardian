# OpenClaw Guardian 完整部署指南

> **目标**：为 OpenClaw 添加双层安全防护 — Layer 1 入口防护（Proxy）+ Layer 2 执行防护（Plugin）

## 架构说明

```
客户端 → Guardian Proxy (:18790) [token 校验] → OpenClaw Gateway (:18789) → Guardian Plugin [blacklist + LLM 投票]
```

**本仓库包含两个组件**：
- **Layer 1 (Entry Protection)**: Proxy 验证 token + Origin，拦截未授权连接
- **Layer 2 (Execution Protection)**: Plugin 在 gateway 内部做 blacklist + LLM 投票

**两者可以独立部署**：
- 只装 Plugin → 只有执行防护（推荐新手先装这个）
- 只装 Proxy → 只有入口防护（不推荐）
- 都装 → 完整双层防护（推荐生产环境）

## 前置条件

- OpenClaw Gateway 正常运行（默认 `127.0.0.1:18789`）
- Node.js >= 18
- 已配置至少一个 LLM provider（用于 Plugin 的 LLM 投票）

## 快速部署

### 步骤 1：克隆仓库并安装依赖

```bash
cd ~/.openclaw/workspace
git clone https://github.com/fatcatMaoFei/openclaw-guardian.git
cd openclaw-guardian
npm install
npm run build
```

### 步骤 2：安装 Plugin（Layer 2 执行防护）

在 `~/.openclaw/openclaw.json` 中添加：

```json
{
  "plugins": {
    "load": {
      "paths": [
        "/home/你的用户名/.openclaw/workspace/openclaw-guardian"
      ]
    },
    "entries": {
      "openclaw-guardian": {
        "enabled": true
      }
    }
  }
}
```

然后重启 gateway：

```bash
openclaw gateway restart
```

验证 Plugin 已加载：

```bash
# 查看日志，应该看到 "openclaw-guardian plugin loaded"
tail -f /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log
```

### 步骤 3：启动 Proxy（Layer 1 入口防护，可选）

**测试模式**（前台运行）：

```bash
npm run start
```

启动后会显示：
```
🛡️  openclaw-guardian: Entry Protection is ONLINE 🛡️
All clients MUST connect to: ws://localhost:18790
Access Token: <your-token>
```

Token 自动保存到 `~/.openclaw/.guardian_token`。

**验证 Token 机制**：

```bash
# 不带 token → 401
curl -i http://localhost:18790/

# 带 token → 200（转发到 gateway）
curl -i "http://localhost:18790/?token=$(cat ~/.openclaw/.guardian_token)"
```

### 步骤 4：配置环境变量（可选）

创建 `.env` 文件：
```env
PROXY_PORT=18790
GUARDIAN_TOKEN=your_custom_token_here
```

如果不设置 `GUARDIAN_TOKEN`，会自动生成并保存到 `~/.openclaw/.guardian_token`。

## 生产部署（systemd）

### 1. 创建 systemd service

```bash
cat > ~/.config/systemd/user/openclaw-guardian-proxy.service <<'EOF'
[Unit]
Description=OpenClaw Guardian Proxy (Entry Protection)
After=openclaw-gateway.service
Requires=openclaw-gateway.service

[Service]
Type=simple
WorkingDirectory=%h/.openclaw/workspace/openclaw-guardian
ExecStart=/usr/bin/node -e "import('./dist/src/proxy-server.js').then(m => m.startProxy())"
Environment="PROXY_PORT=18790"
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
```

### 2. 启用并启动服务

```bash
systemctl --user daemon-reload
systemctl --user enable openclaw-guardian-proxy
systemctl --user start openclaw-guardian-proxy
systemctl --user status openclaw-guardian-proxy
```

### 3. 查看日志

```bash
journalctl --user -u openclaw-guardian-proxy -f
```

## 客户端配置

**如果启用了 Proxy（Layer 1），所有客户端必须从 18789 切换到 18790 + token**：

| 客户端类型 | 原地址 | 新地址 |
|-----------|--------|--------|
| WebSocket | `ws://localhost:18789` | `ws://localhost:18790?token=YOUR_TOKEN` |
| HTTP | `http://localhost:18789/path` | `http://localhost:18790/path?token=YOUR_TOKEN` |
| Telegram webhook | `:18789/tg` | `:18790/tg?token=YOUR_TOKEN` |

或使用 HTTP Header：
```
Authorization: Bearer YOUR_TOKEN
```

**重要**：
- **Telegram polling 模式**：不受影响，无需修改配置
- **Telegram webhook 模式**：需要更新 webhook URL 到 18790 端口

**如果只装了 Plugin（Layer 2），客户端配置无需修改**，继续连接 18789 即可。

## 验证部署

### 1. 检查 Plugin 是否生效

```bash
# 查看 gateway 日志，应该看到 Guardian 拦截记录
tail -f /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log | grep -i guardian

# 查看审计日志
tail -f ~/.openclaw/guardian-audit.jsonl
```

### 2. 检查 Proxy 端口监听（如果启用了 Proxy）

```bash
ss -ltnp | grep -E "18789|18790"
```

应该看到：
- `18789` - OpenClaw Gateway（只监听 127.0.0.1）
- `18790` - Guardian Proxy（只监听 127.0.0.1）

### 3. 测试 WebSocket 连接（如果启用了 Proxy）

```bash
# 安装 wscat（如果没有）
npm install -g wscat

# 不带 token → 401
wscat -c ws://localhost:18790

# 带 token → 成功连接
wscat -c "ws://localhost:18790?token=$(cat ~/.openclaw/.guardian_token)"
```

## 回滚方案

### 回滚 Plugin（Layer 2）

```bash
# 在 openclaw.json 中禁用插件
# "openclaw-guardian": { "enabled": false }

# 重启 gateway
openclaw gateway restart
```

### 回滚 Proxy（Layer 1）

```bash
# 停止 proxy
systemctl --user stop openclaw-guardian-proxy

# 客户端改回直连 18789
# （Telegram polling 模式无需改动）

# Gateway 继续正常运行
```

## 故障排查

### Plugin 未加载

```bash
# 检查 gateway 日志
tail -n 100 /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log | grep -i plugin

# 检查 openclaw.json 配置
cat ~/.openclaw/openclaw.json | grep -A 10 "openclaw-guardian"

# 确认目录路径正确
ls -la ~/.openclaw/workspace/openclaw-guardian/
```

### Proxy 启动失败

```bash
# 检查端口占用
ss -ltnp | grep 18790

# 检查 gateway 是否运行
openclaw gateway status

# 查看详细日志
journalctl --user -u openclaw-guardian-proxy -n 50
```

### Token 验证失败

```bash
# 确认 token 文件存在
cat ~/.openclaw/.guardian_token

# 手动测试
curl -i "http://localhost:18790/?token=$(cat ~/.openclaw/.guardian_token)"
```

### 客户端连接被拒

检查：
1. 是否带了正确的 token
2. Origin 是否为 `localhost` / `127.0.0.1` / `null`（proxy 只允许本地连接）
3. Gateway (18789) 是否正常运行
4. 如果只装了 Plugin，确认客户端连的是 18789 而不是 18790

## 安全建议

1. **Token 保护**：`~/.openclaw/.guardian_token` 权限应为 `600`（只有当前用户可读）
2. **只监听 loopback**：Proxy 和 Gateway 都应只绑定 `127.0.0.1`，不对外暴露
3. **定期轮换 token**：如果怀疑 token 泄露，删除 `~/.openclaw/.guardian_token` 并重启 proxy（会自动生成新 token）
4. **审计日志**：所有连接尝试和工具调用拦截记录在 `~/.openclaw/guardian-audit.jsonl`
5. **Agent 自律规则**：在 `AGENTS.md` 中添加 Guardian 三重防护协议（见 README.md）

## 性能影响

### Plugin（Layer 2）
- **无匹配**：0ms（99% 的操作）
- **Warning 级别**：~1-2s（1 次 LLM 调用）
- **Critical 级别**：~2-4s（3 次并行 LLM 调用）

### Proxy（Layer 1）
- **延迟**：< 1ms（本地转发）
- **吞吐**：无明显影响（纯转发，无 LLM 调用）
- **资源**：~20MB 内存

## 已知问题

1. **ESM 配置**：`src/start.ts` 的 import 路径需要去掉 `.js` 后缀才能用 `ts-node` 运行
2. **编译输出**：`tsc` 会输出到 `dist/src/` 而不是 `dist/`（因为 `tsconfig.json` 的 `rootDir: "."`）
3. **端口冲突**：如果 18790 被占用，修改 `.env` 中的 `PROXY_PORT`
4. **LLM 依赖**：Plugin 需要至少一个可用的 LLM provider，否则 critical 级别操作会被直接拦截

## 推荐部署方案

### 新手/测试环境
- 只装 **Plugin（Layer 2）**
- 客户端继续连 18789
- 体验执行防护功能

### 生产环境
- 同时装 **Plugin + Proxy（Layer 1 + Layer 2）**
- 客户端切换到 18790 + token
- 完整双层防护

### 公网暴露场景
- **必须装 Proxy（Layer 1）**
- 配合防火墙规则
- 定期轮换 token

## 更新日志

- **2026-03-09**: 统一部署指南，Plugin 和 Proxy 共用同一个仓库目录
- **2026-03-05**: 初始部署指南，验证核心功能（token 校验 + 转发）
