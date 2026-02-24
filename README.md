# MCP Sequential Thinking Server (Cloudflare Workers KV Edition)

A production-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server implementation that provides structured, step-by-step thinking for problem-solving. Built for Cloudflare Workers with KV persistence and OAuth 2.0 authentication.

## Features

- **Sequential Thinking**: Break down complex problems into manageable steps
- **Session Persistence**: KV-backed session storage with automatic expiration (1 hour TTL)
- **Revision & Branching**: Support for revising previous thoughts and exploring alternative reasoning paths
- **Tool Recommendations**: AI-powered suggestions for relevant MCP tools based on thought context
- **OAuth 2.0 Authentication**: Secure access with GitHub, Google, or custom OAuth providers
- **MCP 2025-11-25 Compliant**: Full implementation of MCP protocol specification (supports 2025-11-25, 2025-06-18, 2024-11-05)
- **SSE Transport**: Server-Sent Events for real-time communication
- **TypeScript**: Fully typed implementation with strict error handling

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│   Cloudflare Worker  │────▶│   KV Namespace  │
│  (Claude, etc)  │◀────│  (This Server)       │◀────│   (Sessions)    │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────┐
                        │ OAuth Provider│
                        │ (GitHub/Google)│
                        └──────────────┘
```

## Quick Start

### Prerequisites

1. A Cloudflare account
2. A GitHub or Google OAuth application (for authentication)
3. Node.js 20+ and npm

### One-Click Deploy

Click the button below to deploy to Cloudflare Workers:

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/YOUR_USERNAME/mcp-sequential-thinking)

> **Note**: Replace `YOUR_USERNAME` with your GitHub username after forking this repository.

### Manual Deployment

#### 1. Clone and Install

```bash
git clone https://github.com/EtAorangE/mcp-sequential-thinking.git
cd mcp-sequential-thinking
npm install
```

#### 2. Create KV Namespace

```bash
# Login to Cloudflare
npx wrangler login

# Create KV namespace
npx wrangler kv:namespace create "THINKING_KV"
```

Copy the namespace ID from the output and update `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "THINKING_KV"
id = "your-kv-namespace-id"
```

#### 3. Configure OAuth

**For GitHub OAuth:**

1. Go to GitHub Settings → Developer settings → OAuth Apps → New OAuth App
2. Set Authorization callback URL: `https://your-worker.workers.dev/auth/callback`
3. Copy Client ID and generate Client Secret

**For Google OAuth:**

1. Go to Google Cloud Console → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID
3. Add authorized redirect URI: `https://your-worker.workers.dev/auth/callback`
4. Copy Client ID and Client Secret

#### 4. Set Secrets

```bash
# Set OAuth secrets
npx wrangler secret put OAUTH_CLIENT_ID
npx wrangler secret put OAUTH_CLIENT_SECRET
npx wrangler secret put OAUTH_REDIRECT_URI  # e.g., https://your-worker.workers.dev/auth/callback
npx wrangler secret put SESSION_SECRET      # Random string for JWT signing

# Optional: Set OAuth provider (default: github)
npx wrangler secret put OAUTH_PROVIDER
```

#### 5. Deploy

```bash
npm run deploy
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_CLIENT_ID` | Yes | OAuth client ID from your provider |
| `OAUTH_CLIENT_SECRET` | Yes | OAuth client secret |
| `OAUTH_REDIRECT_URI` | Yes | Callback URL (must match OAuth app settings) |
| `SESSION_SECRET` | Yes | Secret key for JWT signing (32+ chars recommended) |
| `OAUTH_PROVIDER` | No | OAuth provider: `github`, `google`, or `custom` (default: `github`) |
| `OAUTH_AUTH_URL` | Custom only | Authorization endpoint URL |
| `OAUTH_TOKEN_URL` | Custom only | Token endpoint URL |
| `OAUTH_USER_URL` | Custom only | User info endpoint URL |

### wrangler.toml

```toml
name = "mcp-sequential-thinking"
main = "index.ts"
compatibility_date = "2024-11-05"
compatibility_flags = ["nodejs_compat"]

[[kv_namespaces]]
binding = "THINKING_KV"
id = "your-kv-namespace-id"

[dev]
port = 8787
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Home page with auth status |
| `/health` | GET | No | Health check |
| `/sse` | GET | Yes | SSE connection endpoint |
| `/messages` | POST | Yes | JSON-RPC message endpoint |
| `/auth/login` | GET | No | Initiate OAuth login |
| `/auth/callback` | GET | No | OAuth callback handler |
| `/auth/logout` | GET | No | Logout and clear session |
| `/auth/me` | GET | Optional | Get current user info |

## MCP Protocol

### Initialize

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {}
  }
}
```

### List Tools

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list"
}
```

### Call Tool

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "sequentialthinking",
    "arguments": {
      "thought": "First, I need to understand the problem...",
      "thoughtNumber": 1,
      "totalThoughts": 5,
      "nextThoughtNeeded": true,
      "available_mcp_tools": ["search", "browser", "file"]
    }
  }
}
```

## Local Development

```bash
# Start local development server
npm run dev

# View logs
npm run tail
```

## CI/CD with GitHub Actions

This project includes a GitHub Actions workflow for automatic deployment.

### Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token with Workers edit permissions |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare account ID |
| `CLOUDFLARE_KV_NAMESPACE_ID` | KV namespace ID |
| `OAUTH_CLIENT_ID` | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | OAuth client secret |
| `OAUTH_REDIRECT_URI` | OAuth callback URL |
| `SESSION_SECRET` | JWT signing secret |

### Deployment Flow

1. Push to `main` branch triggers deployment
2. GitHub Actions builds and deploys to Cloudflare Workers
3. Health check verifies deployment success

## Security Considerations

- All MCP endpoints require authentication
- Session tokens expire after 24 hours
- KV sessions have 1-hour TTL
- OAuth state parameter prevents CSRF attacks
- User isolation in KV storage

## License

MIT License
