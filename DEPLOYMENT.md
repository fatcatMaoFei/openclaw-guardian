# OpenClaw Guardian Proxy 部署指南

> **目标**：为 OpenClaw Gateway 添加入口防护层（Layer 1），所有客户端必须带 token 连接 proxy，防止外部攻击/恶意 JS 直连 gateway。

## 架构

```
客户端 → Guardian Proxy (:18790) [token 校验] → OpenClaw Gateway (:18789)
```

- **Layer 1 (Entry Protection)**: Proxy 验证 token + Origin，拦截未授权连接
- **Layer 2 (Execution Protection)**: Guardian 插件在 gateway 内部做 blacklist + LLM 投票

## 前置条件

- OpenClaw Gateway 正常运行（默认 `127.0.0.1:18789`）
- Node.js >= 18
- 已安装 `openclaw-guardian` 插件（执行防护层）

## 快速部署

### 1. 克隆并安装依赖

```bash
cd ~/.openclaw/workspace
git clone https://github.com/fatcatMaoFei/openclaw-guardian.git openclaw-guardian-proxy
cd openclaw-guardian-proxy
npm install
npm run build
```

### 2. 启动 Proxy（测试）

```bash
# 默认端口 18790，转发到 18789
npm run start
```

启动后会显示：
```
🛡️  openclaw-guardian: Entry Protection is ONLINE 🛡️
All clients MUST connect to: ws://localhost:18790
Access Token: <your-token>
```

Token 自动保存到 `~/.openclaw/.guardian_token`。

### 3. 验证 Token 机制

```bash
# 不带 token → 401
curl -i http://localhost:18790/

# 带 token → 200（转发到 gateway）
curl -i "http://localhost:18790/?token=$(cat ~/.openclaw/.guardian_token)"
```

### 4. 配置环境变量（可选）

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
WorkingDirectory=%h/.openclaw/workspace/openclaw-guardian-proxy
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

**所有客户端必须从 18789 切换到 18790 + token**：

| 客户端类型 | 原地址 | 新地址 |
|-----------|--------|--------|
| WebSocket | `ws://localhost:18789` | `ws://localhost:18790?token=YOUR_TOKEN` |
| HTTP | `http://localhost:18789/path` | `http://localhost:18790/path?token=YOUR_TOKEN` |
| Telegram webhook | `:18789/tg` | `:18790/tg?token=YOUR_TOKEN` |

或使用 HTTP Header：
```
Authorization: Bearer YOUR_TOKEN
```

## 验证部署

### 1. 检查端口监听

```bash
ss -ltnp | grep -E "18789|18790"
```

应该看到：
- `18789` - OpenClaw Gateway（只监听 127.0.0.1）
- `18790` - Guardian Proxy（只监听 127.0.0.1）

### 2. 测试 WebSocket 连接

```bash
# 安装 wscat（如果没有）
npm install -g wscat

# 不带 token → 401
wscat -c ws://localhost:18790

# 带 token → 成功连接
wscat -c "ws://localhost:18790?token=$(cat ~/.openclaw/.guardian_token)"
```

### 3. 测试 Telegram（如果使用）

确认 Telegram 消息能正常收发。如果不通，检查：
- Telegram 是 polling 模式（不受影响）还是 webhook 模式（需要更新 webhook URL）
- Gateway 日志：`tail -f /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log`

## 回滚方案

如果 proxy 有问题，立刻回滚：

```bash
# 停止 proxy
systemctl --user stop openclaw-guardian-proxy

# 客户端改回直连 18789
# （Telegram polling 模式无需改动）

# Gateway 继续正常运行
```

## 故障排查

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

## 安全建议

1. **Token 保护**：`~/.openclaw/.guardian_token` 权限应为 `600`（只有当前用户可读）
2. **只监听 loopback**：Proxy 和 Gateway 都应只绑定 `127.0.0.1`，不对外暴露
3. **定期轮换 token**：如果怀疑 token 泄露，删除 `~/.openclaw/.guardian_token` 并重启 proxy（会自动生成新 token）
4. **审计日志**：所有连接尝试记录在 `~/.openclaw/guardian-audit.jsonl`

## 性能影响

- **延迟**：< 1ms（本地转发）
- **吞吐**：无明显影响（纯转发，无 LLM 调用）
- **资源**：~20MB 内存

## 已知问题

1. **ESM 配置**：`src/start.ts` 的 import 路径需要去掉 `.js` 后缀才能用 `ts-node` 运行
2. **编译输出**：`tsc` 会输出到 `dist/src/` 而不是 `dist/`（因为 `tsconfig.json` 的 `rootDir: "."`）
3. **端口冲突**：如果 18790 被占用，修改 `.env` 中的 `PROXY_PORT`

## 更新日志

- **2026-03-05**: 初始部署指南，验证核心功能（token 校验 + 转发）
