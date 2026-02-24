# AI Agent 开发流程指南

> 本文档定义了 AI Agent 在项目开发、部署、审查、测试过程中的标准化流程和最佳实践。

---

## 目录

1. [概述](#概述)
2. [开发流程](#开发流程)
3. [部署流程](#部署流程)
4. [审查流程](#审查流程)
5. [测试流程](#测试流程)
6. [问题诊断与修复](#问题诊断与修复)
7. [检查清单](#检查清单)
8. [案例复盘](#案例复盘)

---

## 概述

### 核心原则

1. **先验证，后部署** - 本地测试通过后再推送
2. **增量修改** - 每次只改一个问题，立即验证
3. **日志驱动** - 遇到问题先看日志，再行动
4. **配置分离** - 敏感信息使用 Secrets，不硬编码
5. **回滚优先** - 部署失败时，优先恢复稳定版本

### 工作流程图

```
开发 → 本地验证 → 提交 → CI/CD → 部署 → 验证 → 监控
  ↑                                              ↓
  └──────────── 问题修复 ←─── 诊断 ←─── 报警 ←───┘
```

---

## 开发流程

### Phase 1: 需求分析

#### 1.1 需求确认清单

```
□ 功能需求是否明确？
□ 技术栈是否确定？
□ 是否有参考实现？
□ 是否有 API 文档？
□ 是否有设计规范？
```

#### 1.2 技术选型评估

| 维度 | 评估项 | 权重 |
|------|--------|------|
| 可行性 | 技术是否成熟稳定 | 30% |
| 复杂度 | 实现难度是否合理 | 25% |
| 可维护性 | 是否易于维护扩展 | 20% |
| 性能 | 是否满足性能要求 | 15% |
| 成本 | 资源成本是否可控 | 10% |

### Phase 2: 代码开发

#### 2.1 编码前准备

```bash
# 1. 确认开发环境
node --version
npm --version
git status

# 2. 拉取最新代码
git pull origin main

# 3. 创建功能分支
git checkout -b feature/xxx
```

#### 2.2 编码规范

**TypeScript 规范**
```typescript
// ✅ 正确：明确的类型定义
interface Env {
  THINKING_KV?: KVNamespace;
  OAUTH_ISSUER: string;
  JWT_SECRET: string;
}

// ❌ 错误：使用 any
let body: any;
body = await request.json();

// ✅ 正确：精确的类型
let body: Record<string, unknown>;
body = await request.json() as Record<string, unknown>;
```

**错误处理规范**
```typescript
// ✅ 正确：完整的错误处理
async function handleRequest(request: Request, env: Env): Promise<Response> {
  try {
    // 业务逻辑
    return new Response(JSON.stringify(result));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return new Response(JSON.stringify({ error: message }), { status: 500 });
  }
}
```

**递归函数规范**
```typescript
// ❌ 错误：无限递归
async function kvGet(env: Env, key: string) {
  if (env.THINKING_KV) {
    return await kvGet(env, key); // 调用自身！
  }
}

// ✅ 正确：调用实际方法
async function kvGet(env: Env, key: string) {
  if (env.THINKING_KV) {
    return await env.THINKING_KV.get(key);
  }
}
```

#### 2.3 本地验证

```bash
# TypeScript 类型检查
npx tsc --noEmit

# 本地运行测试
npm test

# 本地启动开发服务器
npm run dev
```

---

## 部署流程

### Phase 3: 部署准备

#### 3.1 环境配置检查

**必须确认的配置项**

```
□ CLOUDFLARE_API_TOKEN - 是否有正确的权限？
□ CLOUDFLARE_ACCOUNT_ID - 是否是正确的账户？
□ CLOUDFLARE_KV_NAMESPACE_ID - KV 是否已创建？
□ 其他 Secrets - 是否都已配置？
```

**常见配置错误**

| 错误现象 | 原因 | 解决方案 |
|----------|------|----------|
| `Unable to authenticate` | API Token 无效或权限不足 | 重新创建 Token |
| `KV namespace not valid` | KV ID 错误或未创建 | 检查 KV Namespace |
| `object identifier invalid` | Account ID 错误 | 确认正确的 ID |

#### 3.2 配置文件冲突检查

**关键问题：仓库中的配置文件可能覆盖 CI/CD 生成的配置**

```bash
# 检查是否存在冲突的配置文件
ls -la wrangler.toml worker.toml

# 如果存在，删除或移到其他位置
rm wrangler.toml
```

**最佳实践：配置文件生成策略**

```yaml
# GitHub Actions 中动态生成配置
- name: Create wrangler.toml
  run: |
    cat > wrangler.toml << EOF
    name = "my-worker"
    main = "index.ts"
    
    [[kv_namespaces]]
    binding = "MY_KV"
    id = "${{ secrets.KV_NAMESPACE_ID }}"
    
    [vars]
    ENV_VAR = "${{ secrets.ENV_VAR }}"
    EOF
```

#### 3.3 Account ID vs Subdomain 区分

**关键概念**

| 概念 | 格式 | 用途 |
|------|------|------|
| Account ID | `aa7021b530d3722d45d584c87f7c2648` | API 调用、认证 |
| Workers Subdomain | `978039181` | Worker URL 构造 |

**Worker URL 构造规则**
```
https://{worker-name}.{subdomain}.workers.dev
```

**常见错误**
```yaml
# ❌ 错误：用 Account ID 构造 URL
OAUTH_ISSUER = "https://my-worker.${{ secrets.CLOUDFLARE_ACCOUNT_ID }}.workers.dev"

# ✅ 正确：使用 Subdomain
OAUTH_ISSUER = "https://my-worker.978039181.workers.dev"
```

### Phase 4: 执行部署

#### 4.1 部署前检查清单

```
□ TypeScript 编译无错误
□ 本地测试通过
□ 配置文件已检查
□ Secrets 已正确配置
□ 没有硬编码的敏感信息
□ 没有冲突的配置文件
```

#### 4.2 部署命令

```bash
# 触发部署
git add -A
git commit -m "feat: xxx"
git push origin main
```

#### 4.3 部署状态监控

```bash
# 检查 GitHub Actions 状态
curl -s "https://api.github.com/repos/{owner}/{repo}/actions/runs?per_page=1" \
  -H "Authorization: token {token}" | jq '.workflow_runs[0] | {status, conclusion}'
```

#### 4.4 部署后验证

```bash
# 1. 健康检查
curl -s https://your-worker.workers.dev/health

# 2. 功能验证
curl -s https://your-worker.workers.dev/.well-known/oauth-protected-resource

# 3. 端到端测试
# 注册客户端 -> 获取 Token -> 调用 API
```

---

## 审查流程

### Phase 5: 代码审查

#### 5.1 自动化检查

**TypeScript 检查**
```bash
npx tsc --noEmit
```

**常见 TypeScript 错误**

| 错误 | 原因 | 修复 |
|------|------|------|
| `is of type 'unknown'` | 未指定类型 | 添加类型断言 |
| `is declared but never read` | 未使用变量 | 删除或使用 `_` 前缀 |
| `Type X is not assignable to type Y` | 类型不匹配 | 修正类型 |

**ESLint 检查**
```bash
npx eslint src/ --ext .ts
```

#### 5.2 安全审查

**敏感信息检查**
```bash
# 检查是否有硬编码的密钥
grep -r "secret\|password\|token\|key" --include="*.ts" --exclude-dir=node_modules

# 检查是否有真实的 ID
grep -r "[a-f0-9]{32}" --include="*.ts" --exclude-dir=node_modules
```

**OAuth 安全检查清单**

```
□ Token 有效期是否合理？（建议 1 小时）
□ PKCE 是否正确实现？
□ client_secret 是否安全存储？
□ redirect_uri 是否验证？
□ 是否有 rate limiting？
```

#### 5.3 配置审查

**wrangler.toml 审查**
```toml
# ❌ 错误：硬编码的值
[[kv_namespaces]]
binding = "THINKING_KV"
id = "abc123def456"  # 硬编码！

[vars]
JWT_SECRET = "my-secret"  # 硬编码！

# ✅ 正确：使用占位符或 Secrets
# 配置在 CI/CD 中动态生成
```

**GitHub Actions 审查**
```yaml
# ❌ 错误：暴露 Secrets
run: echo "Token is ${{ secrets.API_TOKEN }}"

# ✅ 正确：使用环境变量
env:
  API_TOKEN: ${{ secrets.API_TOKEN }}
run: ./deploy.sh
```

---

## 测试流程

### Phase 6: 测试策略

#### 6.1 测试金字塔

```
        /\
       /  \      E2E 测试 (10%)
      /----\     
     /      \    集成测试 (20%)
    /--------\
   /          \  单元测试 (70%)
  /------------\
```

#### 6.2 单元测试

**测试框架选择**
```bash
npm install -D vitest @vitest/coverage-v8
```

**测试示例**
```typescript
// tests/oauth.test.ts
import { describe, it, expect } from 'vitest';

describe('OAuth Client Registration', () => {
  it('should generate valid client credentials', async () => {
    const clientId = crypto.randomUUID();
    const clientSecret = crypto.randomUUID().replace(/-/g, '');
    
    expect(clientId).toMatch(/^[0-9a-f-]{36}$/);
    expect(clientSecret).toHaveLength(32);
  });
  
  it('should reject invalid JSON', async () => {
    const request = new Request('http://localhost/oauth/register', {
      method: 'POST',
      body: 'invalid json'
    });
    
    const response = await handleClientRegistration(request, mockEnv);
    expect(response.status).toBe(400);
  });
});
```

#### 6.3 集成测试

**API 端点测试**
```typescript
// tests/api.test.ts
describe('API Endpoints', () => {
  const baseUrl = 'http://localhost:8787';
  
  it('GET /health should return 200', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.status).toBe('ok');
  });
  
  it('POST /oauth/register should create client', async () => {
    const res = await fetch(`${baseUrl}/oauth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Test',
        redirect_uris: ['http://localhost/callback']
      })
    });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.client_id).toBeDefined();
    expect(data.client_secret).toBeDefined();
  });
});
```

#### 6.4 端到端测试

**完整流程测试脚本**
```bash
#!/bin/bash
# e2e-test.sh

BASE_URL="https://your-worker.workers.dev"

echo "=== E2E Test Start ==="

# 1. 健康检查
echo "1. Health Check..."
HEALTH=$(curl -s "$BASE_URL/health")
echo "   Response: $HEALTH"

# 2. 注册客户端
echo "2. Register Client..."
CLIENT=$(curl -s -X POST "$BASE_URL/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"E2E Test","redirect_uris":["http://localhost/callback"]}')
CLIENT_ID=$(echo $CLIENT | jq -r '.client_id')
CLIENT_SECRET=$(echo $CLIENT | jq -r '.client_secret')
echo "   Client ID: $CLIENT_ID"

# 3. 获取 Token
echo "3. Get Token..."
TOKEN=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=mcp:tools")
ACCESS_TOKEN=$(echo $TOKEN | jq -r '.access_token')
echo "   Token: ${ACCESS_TOKEN:0:20}..."

# 4. MCP 初始化
echo "4. MCP Initialize..."
INIT=$(curl -s -X POST "$BASE_URL/messages" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}')
echo "   Response: $INIT"

# 5. 验证结果
if echo "$INIT" | jq -e '.result.serverInfo' > /dev/null; then
  echo "=== E2E Test PASSED ==="
  exit 0
else
  echo "=== E2E Test FAILED ==="
  exit 1
fi
```

#### 6.5 测试覆盖率

```bash
# 运行覆盖率测试
npx vitest run --coverage

# 覆盖率目标
# - 语句覆盖率: > 80%
# - 分支覆盖率: > 70%
# - 函数覆盖率: > 80%
# - 行覆盖率: > 80%
```

---

## 问题诊断与修复

### Phase 7: 问题诊断流程

#### 7.1 诊断步骤

```
1. 获取错误日志
   ↓
2. 定位错误类型
   ↓
3. 分析根本原因
   ↓
4. 制定修复方案
   ↓
5. 验证修复效果
```

#### 7.2 日志获取方法

**GitHub Actions 日志**
```bash
# 获取最新的运行 ID
RUN_ID=$(curl -s "https://api.github.com/repos/{owner}/{repo}/actions/runs?per_page=1" \
  -H "Authorization: token {token}" | jq '.workflow_runs[0].id')

# 获取 Job ID
JOB_ID=$(curl -s "https://api.github.com/repos/{owner}/{repo}/actions/runs/$RUN_ID/jobs" \
  -H "Authorization: token {token}" | jq '.jobs[0].id')

# 获取日志
curl -s -H "Authorization: token {token}" \
  "https://api.github.com/repos/{owner}/{repo}/actions/jobs/$JOB_ID/logs"
```

**Cloudflare Workers 日志**
```bash
# 使用 wrangler tail 实时查看日志
npx wrangler tail

# 或在 Dashboard 查看
# Workers & Pages → your-worker → Logs
```

#### 7.3 常见错误速查表

| 错误码 | 错误信息 | 原因 | 解决方案 |
|--------|----------|------|----------|
| 10001 | Unable to authenticate | API Token 无效 | 检查 Token 权限 |
| 10042 | KV namespace not valid | KV ID 错误 | 检查 KV Namespace |
| 7003 | Object identifier invalid | Account ID 错误 | 确认正确 ID |
| 1101 | Worker threw exception | 代码运行时错误 | 检查代码逻辑 |
| - | Maximum call stack exceeded | 无限递归 | 检查递归函数 |

#### 7.4 修复验证流程

```bash
# 1. 本地验证
npx tsc --noEmit
npm test

# 2. 提交修复
git add -A
git commit -m "fix: xxx"
git push

# 3. 等待部署
sleep 50

# 4. 验证修复
curl -s https://your-worker.workers.dev/health

# 5. 如果失败，回滚
git revert HEAD
git push
```

---

## 检查清单

### 部署前检查清单

```
□ 代码质量
  □ TypeScript 编译无错误
  □ ESLint 检查通过
  □ 没有 console.log 调试代码
  □ 没有硬编码的敏感信息

□ 配置检查
  □ GitHub Secrets 已配置
  □ 没有冲突的配置文件
  □ Account ID 正确
  □ KV Namespace ID 正确

□ 测试检查
  □ 单元测试通过
  □ 集成测试通过
  □ 本地运行正常

□ 文档检查
  □ README 已更新
  □ API 文档已更新
  □ 变更日志已更新
```

### 部署后检查清单

```
□ 健康检查
  □ /health 返回正常
  □ KV 连接正常

□ 功能验证
  □ OAuth 注册正常
  □ Token 获取正常
  □ MCP 调用正常

□ 监控检查
  □ 没有错误日志
  □ 响应时间正常
```

---

## 案例复盘

### 案例：MCP Sequential Thinking Server 部署

#### 项目背景
- 目标：部署一个支持 OAuth 2.0 的 MCP 服务器到 Cloudflare Workers
- 技术栈：TypeScript, Cloudflare Workers, KV Namespace

#### 遇到的问题

**问题 1: TypeScript 编译错误**
```
现象: 多处类型错误
原因: unknown 类型未处理、未使用变量
解决: 添加类型断言、使用 _ 前缀
耗时: 30 分钟
```

**问题 2: API Token 权限不足**
```
现象: Unable to authenticate request [code: 10001]
原因: Token 缺少 Workers 编辑权限
解决: 重新创建 Token，选择 Edit Workers 模板
耗时: 20 分钟
```

**问题 3: KV Namespace 配置错误**
```
现象: KV namespace 'YOUR_KV_NAMESPACE_ID' is not valid
原因: 仓库中的 wrangler.toml 包含占位符
解决: 删除 wrangler.toml，在 CI/CD 中动态生成
耗时: 40 分钟
```

**问题 4: Account ID 混淆**
```
现象: OAUTH_ISSUER 指向错误的 URL
原因: 混淆了 Account ID 和 Workers Subdomain
解决: 使用 Subdomain 构造 URL
耗时: 30 分钟
```

**问题 5: 无限递归**
```
现象: Maximum call stack size exceeded
原因: kvGet 函数调用自身
解决: 修改为调用 env.THINKING_KV.get()
耗时: 15 分钟
```

#### 经验教训

| 类别 | 教训 | 改进措施 |
|------|------|----------|
| 开发 | 递归函数容易出错 | 添加代码审查规则 |
| 配置 | 配置文件冲突 | 使用动态生成策略 |
| 部署 | Account ID 概念不清 | 添加文档说明 |
| 测试 | 缺少本地测试 | 添加测试脚本 |
| 监控 | 错误定位慢 | 添加结构化日志 |

#### 改进建议

1. **开发阶段**
   - 添加 pre-commit hook 进行类型检查
   - 使用 ESLint 规则检测无限递归

2. **配置管理**
   - 统一使用 CI/CD 生成配置
   - 添加配置验证步骤

3. **测试流程**
   - 添加本地端到端测试脚本
   - 添加部署后自动验证

4. **文档完善**
   - 添加概念说明文档
   - 添加故障排查指南

---

## 附录

### A. 常用命令速查

```bash
# TypeScript 检查
npx tsc --noEmit

# 本地开发
npm run dev

# 部署
git push origin main

# 查看日志
npx wrangler tail

# 本地测试
npm test

# 覆盖率测试
npx vitest run --coverage
```

### B. 环境变量模板

```env
# .env.example
CLOUDFLARE_API_TOKEN=your-api-token
CLOUDFLARE_ACCOUNT_ID=your-account-id
CLOUDFLARE_KV_NAMESPACE_ID=your-kv-namespace-id
JWT_SECRET=your-jwt-secret-min-32-chars
```

### C. GitHub Actions 模板

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Type check
        run: npx tsc --noEmit
      
      - name: Run tests
        run: npm test
      
      - name: Create config
        run: |
          cat > wrangler.toml << EOF
          name = "my-worker"
          main = "index.ts"
          [[kv_namespaces]]
          binding = "MY_KV"
          id = "${{ secrets.KV_NAMESPACE_ID }}"
          EOF
      
      - name: Deploy
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
      
      - name: Verify
        run: curl -s https://my-worker.workers.dev/health
```

### D. 参考资源

- [Cloudflare Workers 文档](https://developers.cloudflare.com/workers/)
- [MCP 规范](https://modelcontextprotocol.io/)
- [OAuth 2.0 RFC](https://oauth.net/2/)
- [TypeScript 最佳实践](https://www.typescriptlang.org/docs/handbook/declaration-files/do-s-and-don-ts.html)
