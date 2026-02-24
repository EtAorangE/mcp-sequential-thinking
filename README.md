# MCP Sequential Thinking Server

MCP 服务器，支持 OAuth 2.0 认证，部署在 Cloudflare Workers。

## MCP OAuth 2.0 端点

| 端点 | 说明 |
|------|------|
| `/.well-known/oauth-protected-resource` | 受保护资源元数据 (RFC 9728) |
| `/.well-known/oauth-authorization-server` | 授权服务器元数据 |
| `/oauth/register` | 动态客户端注册 (RFC 7591) |
| `/oauth/authorize` | 授权端点 |
| `/oauth/token` | 令牌端点 |
| `/oauth/jwks` | JWKS 公钥 |

## MCP 客户端连接流程

### 1. 注册客户端

```bash
curl -X POST https://your-worker.workers.dev/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "My MCP Client", "redirect_uris": ["http://localhost:3000/callback"]}'
```

返回：
```json
{
  "client_id": "xxx",
  "client_secret": "xxx",
  ...
}
```

### 2. 获取 Access Token

**方式一：客户端凭证模式**
```bash
curl -X POST https://your-worker.workers.dev/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=xxx&client_secret=xxx&scope=mcp:tools"
```

**方式二：授权码模式（带 PKCE）**
```
1. 访问 /oauth/authorize?client_id=xxx&redirect_uri=xxx&code_challenge=xxx&code_challenge_method=S256
2. 获取授权码 code
3. 用 code 换取 token
```

### 3. 连接 MCP

```
Authorization: Bearer <access_token>
```

## 部署

### 1. 创建 KV Namespace

```bash
wrangler kv:namespace create "THINKING_KV"
```

### 2. 设置 Secrets

```bash
wrangler secret put OAUTH_ISSUER  # 例如: https://mcp-sequential-thinking.xxx.workers.dev
wrangler secret put JWT_SECRET    # 随机字符串，32位以上
```

### 3. 部署

```bash
npm install
npm run deploy
```

## 环境变量

| 变量 | 必需 | 说明 |
|------|------|------|
| `OAUTH_ISSUER` | 是 | Worker 的完整 URL |
| `JWT_SECRET` | 是 | JWT 签名密钥 |

## 本地开发

```bash
npm run dev
```
