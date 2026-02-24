# 部署指南

## 一键部署方案

### 方案一：Cloudflare Workers 一键部署按钮

Cloudflare 官方提供了一键部署按钮，可以在 fork 本仓库后直接部署。

1. Fork 本仓库到你的 GitHub 账号
2. 修改 README.md 中的部署按钮链接，将 `YOUR_USERNAME` 替换为你的 GitHub 用户名
3. 点击 README 中的 "Deploy to Cloudflare Workers" 按钮

### 方案二：GitHub Actions 自动部署

本项目已配置 GitHub Actions 自动部署工作流。

#### 步骤 1：创建 Cloudflare API Token

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 My Profile → API Tokens → Create Token
3. 选择 "Edit Cloudflare Workers" 模板
4. 复制生成的 Token

#### 步骤 2：获取 Account ID 和 KV Namespace ID

```bash
# 安装 wrangler
npm install -g wrangler

# 登录
wrangler login

# 获取 Account ID
wrangler whoami

# 创建 KV Namespace
wrangler kv:namespace create "THINKING_KV"
# 复制输出的 namespace ID
```

#### 步骤 3：配置 GitHub Secrets

在你的 GitHub 仓库中，进入 Settings → Secrets and variables → Actions，添加以下 secrets：

| Secret 名称 | 说明 |
|------------|------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API Token |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID |
| `CLOUDFLARE_KV_NAMESPACE_ID` | KV Namespace ID |
| `OAUTH_CLIENT_ID` | OAuth 客户端 ID |
| `OAUTH_CLIENT_SECRET` | OAuth 客户端密钥 |
| `OAUTH_REDIRECT_URI` | OAuth 回调地址 |
| `SESSION_SECRET` | JWT 签名密钥（随机字符串） |

#### 步骤 4：推送代码触发部署

```bash
git push origin main
```

GitHub Actions 会自动构建并部署到 Cloudflare Workers。

### 方案三：手动部署

```bash
# 1. 克隆仓库
git clone https://github.com/YOUR_USERNAME/mcp-sequential-thinking.git
cd mcp-sequential-thinking

# 2. 安装依赖
npm install

# 3. 登录 Cloudflare
npx wrangler login

# 4. 创建 KV Namespace
npx wrangler kv:namespace create "THINKING_KV"
# 更新 wrangler.toml 中的 namespace ID

# 5. 设置 OAuth secrets
npx wrangler secret put OAUTH_CLIENT_ID
npx wrangler secret put OAUTH_CLIENT_SECRET
npx wrangler secret put OAUTH_REDIRECT_URI
npx wrangler secret put SESSION_SECRET

# 6. 部署
npm run deploy
```

## OAuth 配置

### GitHub OAuth

1. 进入 GitHub Settings → Developer settings → OAuth Apps → New OAuth App
2. 填写应用信息：
   - Application name: MCP Sequential Thinking
   - Homepage URL: `https://your-worker.workers.dev`
   - Authorization callback URL: `https://your-worker.workers.dev/auth/callback`
3. 创建后复制 Client ID
4. 生成 Client Secret

### Google OAuth

1. 进入 [Google Cloud Console](https://console.cloud.google.com)
2. 创建项目或选择现有项目
3. 启用 Google+ API
4. 创建 OAuth 2.0 凭据
5. 添加授权重定向 URI: `https://your-worker.workers.dev/auth/callback`
6. 复制 Client ID 和 Client Secret

## 验证部署

部署完成后，访问以下端点验证：

```bash
# 健康检查
curl https://your-worker.workers.dev/health

# 预期响应
{
  "status": "ok",
  "server": "sequential-thinking-kv",
  "version": "1.0.0",
  "protocol": "2024-11-05",
  "auth": "oauth-enabled",
  "timestamp": "2024-..."
}
```

## 故障排除

### 常见问题

1. **KV Namespace 错误**
   - 确保 wrangler.toml 中的 KV namespace ID 正确
   - 确保 KV namespace 已创建

2. **OAuth 认证失败**
   - 检查 OAuth 回调地址是否正确配置
   - 确保 Client ID 和 Secret 正确设置

3. **部署失败**
   - 检查 GitHub Secrets 是否正确配置
   - 查看 GitHub Actions 日志获取详细错误信息
