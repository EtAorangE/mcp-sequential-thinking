# MCP Sequential Thinking Server - Project Documentation

## 项目概述

**MCP Sequential Thinking Server** 是一个基于 Cloudflare Workers 的 Model Context Protocol (MCP) 服务器，实现了 OAuth 2.0 认证和顺序思维工具功能。

- **协议版本**: MCP 2025-11-25
- **传输方式**: HTTP + SSE (Server-Sent Events)
- **认证方式**: OAuth 2.0 (RFC 9728 Protected Resource Metadata)
- **运行环境**: Cloudflare Workers + KV Namespace

---

## 项目架构

```
mcp-sequential-thinking/
├── index.ts                 # 主入口，Worker 代码
├── package.json             # 依赖配置
├── tsconfig.json            # TypeScript 配置
├── .github/
│   └── workflows/
│       └── deploy.yml       # GitHub Actions 部署配置
├── README.md                # 项目说明
├── DEPLOYMENT.md            # 部署文档
└── AGENTS.md                # 本文档
```

---

## 技术实现

### 1. MCP 协议实现

#### 1.1 协议版本支持
```typescript
const MCP_VERSION = '2025-11-25';
const supportedVersions = ['2025-11-25', '2025-06-18', '2024-11-05'];
```

服务器支持多版本协议协商，确保与不同版本的 MCP 客户端兼容。

#### 1.2 JSON-RPC 2.0 实现
- **请求格式**: `{ jsonrpc: "2.0", id, method, params }`
- **响应格式**: `{ jsonrpc: "2.0", id, result/error }`
- **错误码**: 遵循 JSON-RPC 2.0 规范 + MCP 扩展错误码

#### 1.3 支持的方法
| 方法 | 说明 |
|------|------|
| `initialize` | 初始化连接，协商协议版本 |
| `tools/list` | 获取可用工具列表 |
| `tools/call` | 调用指定工具 |
| `ping` | 心跳检测 |

### 2. OAuth 2.0 实现

#### 2.1 端点实现
| 端点 | 路径 | 说明 |
|------|------|------|
| Protected Resource Metadata | `/.well-known/oauth-protected-resource` | RFC 9728 |
| Authorization Server Metadata | `/.well-known/oauth-authorization-server` | RFC 8414 |
| Dynamic Client Registration | `/oauth/register` | RFC 7591 |
| Authorization Endpoint | `/oauth/authorize` | 授权码流程 |
| Token Endpoint | `/oauth/token` | 令牌获取 |
| JWKS Endpoint | `/oauth/jwks` | 公钥验证 |

#### 2.2 支持的授权流程
1. **Client Credentials**: 适用于服务间通信
2. **Authorization Code + PKCE**: 适用于用户授权

#### 2.3 JWT 实现
- **算法**: HS256 (HMAC-SHA256)
- **有效期**: 1 小时
- **载荷**: `{ sub, scope, iat, exp }`

### 3. 数据存储

#### 3.1 KV Namespace 绑定
```typescript
export interface Env {
  THINKING_KV?: KVNamespace;
  OAUTH_ISSUER: string;
  JWT_SECRET: string;
}
```

#### 3.2 存储结构
| Key Pattern | Value | TTL |
|-------------|-------|-----|
| `oauth:client:{clientId}` | OAuthClient JSON | 365 天 |
| `oauth:code:{code}` | AuthCode JSON | 60 秒 |
| `thoughts:{clientId}:{sessionId}` | Thought[] JSON | 1 小时 |

#### 3.3 内存回退机制
当 KV 未配置时，自动使用内存存储（适用于开发环境）。

---

## 部署流程

### 1. 环境准备

#### 1.1 Cloudflare 资源
1. 创建 Cloudflare 账户
2. 获取 Account ID (在 Dashboard 右侧)
3. 创建 API Token (需要 Workers Scripts Edit 权限)
4. 创建 KV Namespace

#### 1.2 GitHub Secrets 配置
| Secret | 说明 |
|--------|------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API Token |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare Account ID |
| `CLOUDFLARE_KV_NAMESPACE_ID` | KV Namespace ID |
| `JWT_SECRET` | JWT 签名密钥 (32+ 字符) |

### 2. 部署步骤

```bash
# 1. 克隆仓库
git clone https://github.com/your-repo/mcp-sequential-thinking.git

# 2. 配置 GitHub Secrets

# 3. 推送代码触发部署
git push origin main
```

### 3. 验证部署

```bash
# 健康检查
curl https://your-worker.workers.dev/health

# OAuth 元数据
curl https://your-worker.workers.dev/.well-known/oauth-protected-resource
```

---

## 开发历程与问题解决

### 问题 1: TypeScript 编译错误

**现象**: 多处类型错误导致部署失败

**原因**: 
- `unknown` 类型未正确处理
- 未使用变量警告
- 类型不匹配

**解决方案**:
```typescript
// 修复前
let body;
body = await request.json();

// 修复后
let body: Record<string, any>;
body = await request.json() as Record<string, any>;
```

### 问题 2: Cloudflare API Token 权限不足

**现象**: `Unable to authenticate request [code: 10001]`

**原因**: API Token 缺少必要权限

**解决方案**:
创建 Token 时选择 **Edit Cloudflare Workers** 模板，确保包含：
- Workers Scripts → Edit
- Workers KV Storage → Edit
- Account Settings → Read

### 问题 3: KV Namespace 配置错误

**现象**: `KV namespace 'YOUR_KV_NAMESPACE_ID' is not valid`

**原因**: 
1. GitHub Secret 未正确设置
2. 仓库中的 `wrangler.toml` 包含占位符值

**解决方案**:
1. 删除仓库中的 `wrangler.toml`
2. 在 GitHub Actions 中动态生成配置

### 问题 4: Account ID vs Workers Subdomain 混淆

**现象**: `OAUTH_ISSUER` 指向错误的 URL

**原因**: 
- Account ID: `aa7021b530d3722d45d584c87f7c2648`
- Workers Subdomain: `978039181`
- Worker URL 使用 Subdomain，而非 Account ID

**解决方案**:
```yaml
# 错误
OAUTH_ISSUER = "https://mcp-sequential-thinking.${{ secrets.CLOUDFLARE_ACCOUNT_ID }}.workers.dev"

# 正确
OAUTH_ISSUER = "https://mcp-sequential-thinking.978039181.workers.dev"
```

### 问题 5: KV Helper 函数无限递归

**现象**: `Maximum call stack size exceeded`

**原因**: 函数内部调用自身

**解决方案**:
```typescript
// 错误
async function kvGet(env: Env, key: string) {
  if (env.THINKING_KV) {
    return await kvGet(env, key); // 无限递归
  }
}

// 正确
async function kvGet(env: Env, key: string) {
  if (env.THINKING_KV) {
    return await env.THINKING_KV.get(key);
  }
}
```

---

## 改进建议

### 1. 安全性增强

#### 1.1 JWT 密钥轮换
```typescript
interface Env {
  JWT_SECRET_CURRENT: string;
  JWT_SECRET_PREVIOUS?: string; // 支持旧密钥验证
}
```

#### 1.2 Token 刷新机制
```typescript
// 添加 refresh_token 支持
interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'Bearer';
}
```

#### 1.3 请求限流
```typescript
// 使用 KV 实现简单限流
async function rateLimit(env: Env, clientId: string): Promise<boolean> {
  const key = `ratelimit:${clientId}`;
  const count = parseInt(await kvGet(env, key) || '0');
  if (count > 100) return false;
  await kvPut(env, key, String(count + 1), { expirationTtl: 60 });
  return true;
}
```

### 2. 功能扩展

#### 2.1 资源支持
```typescript
// 添加 MCP Resources 支持
case 'resources/list':
  return { resources: await listResources(env) };
case 'resources/read':
  return { contents: await readResource(params.uri, env) };
```

#### 2.2 提示词模板
```typescript
// 添加 MCP Prompts 支持
case 'prompts/list':
  return { prompts: PROMPT_TEMPLATES };
case 'prompts/get':
  return { messages: await getPrompt(params.name, params.arguments) };
```

#### 2.3 思维链持久化
```typescript
// 支持跨会话的思维链
interface Session {
  id: string;
  thoughts: Thought[];
  createdAt: number;
  updatedAt: number;
}
```

### 3. 可观测性

#### 3.1 结构化日志
```typescript
function log(level: 'info' | 'warn' | 'error', message: string, data?: any) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    message,
    ...data
  }));
}
```

#### 3.2 性能指标
```typescript
// 添加请求耗时统计
const startTime = Date.now();
// ... 处理请求
const duration = Date.now() - startTime;
log('info', 'Request completed', { method, duration });
```

### 4. 测试覆盖

#### 4.1 单元测试
```typescript
// tests/oauth.test.ts
describe('OAuth', () => {
  it('should register client', async () => {
    const response = await handleClientRegistration(mockRequest, mockEnv);
    expect(response.status).toBe(201);
  });
});
```

#### 4.2 集成测试
```typescript
// tests/mcp.test.ts
describe('MCP Protocol', () => {
  it('should initialize with correct version', async () => {
    const result = await handleInitialize({ protocolVersion: '2025-11-25' });
    expect(result.protocolVersion).toBe('2025-11-25');
  });
});
```

### 5. 文档完善

#### 5.1 API 文档
- OpenAPI/Swagger 规范
- 交互式 API 文档
- 代码示例

#### 5.2 集成指南
- Claude Desktop 集成
- Cursor IDE 集成
- 自定义客户端集成

---

## 最佳实践

### 1. 代码组织

```typescript
// 建议的文件结构
src/
├── index.ts           # 入口
├── mcp/
│   ├── protocol.ts    # MCP 协议实现
│   ├── tools.ts       # 工具定义
│   └── resources.ts   # 资源实现
├── oauth/
│   ├── client.ts      # 客户端管理
│   ├── token.ts       # 令牌管理
│   └── jwt.ts         # JWT 处理
├── storage/
│   └── kv.ts          # KV 封装
└── utils/
    ├── logger.ts      # 日志工具
    └── errors.ts      # 错误处理
```

### 2. 错误处理

```typescript
// 统一错误处理
class McpError extends Error {
  constructor(
    public code: number,
    message: string,
    public data?: any
  ) {
    super(message);
  }
}

// 全局错误捕获
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handleRequest(request, env);
    } catch (error) {
      return handleError(error);
    }
  }
};
```

### 3. 类型安全

```typescript
// 严格的类型定义
interface ToolCallParams {
  name: string;
  arguments: Record<string, unknown>;
}

interface ToolCallResult {
  content: Array<{
    type: 'text' | 'image' | 'resource';
    text?: string;
  }>;
}
```

### 4. 配置管理

```typescript
// 环境变量验证
function validateEnv(env: Env): void {
  if (!env.OAUTH_ISSUER) {
    throw new Error('OAUTH_ISSUER is required');
  }
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters');
  }
}
```

---

## 总结

本项目成功实现了一个符合 MCP 2025-11-25 规范的服务器，具备以下特点：

1. **完整的 OAuth 2.0 支持**: 符合 RFC 9728、RFC 7591 等标准
2. **灵活的存储方案**: 支持 KV 和内存存储
3. **健壮的错误处理**: 完善的异常捕获和恢复机制
4. **自动化部署**: GitHub Actions CI/CD 流程

未来改进方向：
- 增强安全性（密钥轮换、限流）
- 扩展功能（Resources、Prompts）
- 完善测试（单元测试、集成测试）
- 优化文档（API 文档、集成指南）

---

## 附录

### A. 环境变量清单

| 变量 | 必需 | 说明 | 示例 |
|------|------|------|------|
| `CLOUDFLARE_API_TOKEN` | 是 | Cloudflare API Token | `...` |
| `CLOUDFLARE_ACCOUNT_ID` | 是 | Cloudflare Account ID | `aa7021b5...` |
| `CLOUDFLARE_KV_NAMESPACE_ID` | 是 | KV Namespace ID | `abc123...` |
| `JWT_SECRET` | 是 | JWT 签名密钥 | `min-32-chars` |

### B. API 端点清单

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/health` | 否 | 健康检查 |
| GET | `/.well-known/oauth-protected-resource` | 否 | OAuth 元数据 |
| GET | `/.well-known/oauth-authorization-server` | 否 | 授权服务器元数据 |
| POST | `/oauth/register` | 否 | 客户端注册 |
| GET | `/oauth/authorize` | 否 | 授权端点 |
| POST | `/oauth/token` | 否 | 令牌端点 |
| GET | `/oauth/jwks` | 否 | JWKS 公钥 |
| POST | `/messages` | Bearer | MCP 消息端点 |
| GET | `/sse` | Bearer | SSE 连接端点 |

### C. 错误码清单

| 代码 | 名称 | 说明 |
|------|------|------|
| -32700 | PARSE_ERROR | JSON 解析错误 |
| -32600 | INVALID_REQUEST | 无效请求 |
| -32601 | METHOD_NOT_FOUND | 方法不存在 |
| -32602 | INVALID_PARAMS | 无效参数 |
| -32603 | INTERNAL_ERROR | 内部错误 |
| -32000 | TOOL_NOT_FOUND | 工具不存在 |
| -32001 | UNAUTHORIZED | 未授权 |
| -32005 | INVALID_TOOL_INPUT | 无效工具输入 |

### D. 参考资源

- [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 Protected Resource Metadata RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)
- [OAuth 2.0 Dynamic Client Registration RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)
