/**
 * MCP Sequential Thinking Server - Cloudflare Workers KV Edition with OAuth
 * 
 * A Model Context Protocol (MCP) server implementation that provides structured,
 * step-by-step thinking for problem-solving with session persistence via Cloudflare KV.
 * Includes OAuth authentication support for secure access.
 * 
 * Protocol: MCP 2024-11-05
 * Transport: HTTP + SSE (Server-Sent Events)
 * Runtime: Cloudflare Workers
 * Auth: OAuth 2.0 (GitHub, Google, Custom)
 */

export interface Env {
  THINKING_KV: KVNamespace;
  // OAuth configuration
  OAUTH_CLIENT_ID: string;
  OAUTH_CLIENT_SECRET: string;
  OAUTH_REDIRECT_URI: string;
  OAUTH_PROVIDER?: 'github' | 'google' | 'custom';
  // For custom OAuth provider
  OAUTH_AUTH_URL?: string;
  OAUTH_TOKEN_URL?: string;
  OAUTH_USER_URL?: string;
  // Session secret for JWT signing
  SESSION_SECRET: string;
}

// Thought data structure
interface Thought {
  thought: string;
  thoughtNumber: number;
  totalThoughts: number;
  nextThoughtNeeded: boolean;
  isRevision?: boolean;
  revisesThought?: number;
  branchFromThought?: number;
  branchId?: string;
  needsMoreThoughts?: boolean;
  toolRecommendations?: ToolRecommendation[];
  timestamp: number;
}

interface ToolRecommendation {
  tool: string;
  confidence: number;
  rationale: string;
  priority: 'high' | 'medium' | 'low';
}

// User session from OAuth
interface UserSession {
  userId: string;
  username: string;
  email?: string;
  avatar?: string;
  provider: string;
  expiresAt: number;
}

// MCP Protocol Constants
const MCP_VERSION = '2025-11-25';
const SERVER_NAME = 'sequential-thinking-kv';
const SERVER_VERSION = '1.1.0';
const JSONRPC_VERSION = '2.0';

// JSON-RPC Error Codes (Standard + MCP-specific)
const ErrorCode = {
  // Standard JSON-RPC errors
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  // MCP-specific errors
  TOOL_NOT_FOUND: -32000,
  INVALID_TOOL_INPUT: -32005,
  SESSION_NOT_FOUND: -32006,
  UNAUTHORIZED: -32001,
} as const;

// Tool definitions following MCP specification
const TOOLS = [
  {
    name: 'sequentialthinking',
    description: 'Facilitates a detailed, step-by-step thinking process for problem-solving and analysis. Supports revision, branching, and dynamic adjustment of thought count.',
    inputSchema: {
      type: 'object',
      properties: {
        thought: { 
          type: 'string',
          description: 'The current thinking step content'
        },
        nextThoughtNeeded: { 
          type: 'boolean',
          description: 'Whether another thought step is needed'
        },
        thoughtNumber: { 
          type: 'number',
          description: 'Current thought number (1-indexed)'
        },
        totalThoughts: { 
          type: 'number',
          description: 'Estimated total thoughts needed'
        },
        available_mcp_tools: { 
          type: 'array', 
          items: { type: 'string' },
          description: 'List of available MCP tool names for recommendations'
        },
        isRevision: { 
          type: 'boolean',
          description: 'Whether this revises previous thinking'
        },
        revisesThought: { 
          type: 'number',
          description: 'Which thought number is being reconsidered (required if isRevision is true)'
        },
        branchFromThought: { 
          type: 'number',
          description: 'Branching point thought number'
        },
        branchId: { 
          type: 'string',
          description: 'Branch identifier string'
        },
        needsMoreThoughts: { 
          type: 'boolean',
          description: 'If more thoughts are needed beyond current estimate'
        }
      },
      required: ['thought', 'nextThoughtNeeded', 'thoughtNumber', 'totalThoughts', 'available_mcp_tools'],
      additionalProperties: false
    }
  }
];

// JSON-RPC Request/Response types
interface JsonRpcRequest {
  jsonrpc: string;
  id?: string | number | null;
  method: string;
  params?: any;
}

interface JsonRpcResponse {
  jsonrpc: string;
  id?: string | number | null;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400'
        }
      });
    }

    // OAuth routes
    if (url.pathname === '/auth/login') {
      return handleOAuthLogin(request, env);
    }

    if (url.pathname === '/auth/callback') {
      return handleOAuthCallback(request, env);
    }

    if (url.pathname === '/auth/logout') {
      return handleLogout(request, env);
    }

    if (url.pathname === '/auth/me') {
      return handleAuthMe(request, env);
    }

    // SSE endpoint for session establishment
    if (url.pathname === '/sse') {
      const authResult = await checkAuth(request, env);
      if (!authResult.authorized) {
        return createErrorResponse(null, ErrorCode.UNAUTHORIZED, authResult.error || 'Unauthorized', 401);
      }
      return handleSSE(request, authResult.user!);
    }

    // JSON-RPC message endpoint
    if (url.pathname === '/messages') {
      const authResult = await checkAuth(request, env);
      if (!authResult.authorized) {
        return createErrorResponse(null, ErrorCode.UNAUTHORIZED, authResult.error || 'Unauthorized', 401);
      }
      return handleMessages(request, env, authResult.user!);
    }

    // Health check endpoint (no auth required)
    if (url.pathname === '/health') {
      return new Response(
        JSON.stringify({ 
          status: 'ok', 
          server: SERVER_NAME,
          version: SERVER_VERSION,
          protocol: MCP_VERSION,
          auth: 'oauth-enabled',
          timestamp: new Date().toISOString()
        }), 
        {
          status: 200,
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        }
      );
    }

    // Root endpoint - show auth status
    if (url.pathname === '/') {
      return handleRoot(request, env);
    }

    // 404 for unknown paths
    return createErrorResponse(null, ErrorCode.METHOD_NOT_FOUND, `Path not found: ${url.pathname}`, 404);
  }
};

/**
 * Handle root endpoint - show auth status and login link
 */
async function handleRoot(request: Request, env: Env): Promise<Response> {
  const authResult = await checkAuth(request, env);
  const provider = env.OAUTH_PROVIDER || 'github';
  
  let html = `<!DOCTYPE html>
<html>
<head>
  <title>MCP Sequential Thinking Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
    .card { background: #f6f8fa; border-radius: 8px; padding: 20px; margin: 20px 0; }
    .btn { display: inline-block; padding: 10px 20px; background: #0366d6; color: white; text-decoration: none; border-radius: 6px; }
    .btn:hover { background: #0256c5; }
    pre { background: #1f2937; color: #e5e7eb; padding: 15px; border-radius: 6px; overflow-x: auto; }
    code { font-family: 'Menlo', 'Monaco', monospace; }
  </style>
</head>
<body>
  <h1>🧠 MCP Sequential Thinking Server</h1>
  <div class="card">
    <p><strong>Version:</strong> ${SERVER_VERSION}</p>
    <p><strong>Protocol:</strong> MCP ${MCP_VERSION}</p>
    <p><strong>Auth:</strong> OAuth 2.0 (${provider})</p>
  </div>`;

  if (authResult.authorized && authResult.user) {
    html += `
  <div class="card">
    <h2>✅ Authenticated</h2>
    <p><strong>User:</strong> ${authResult.user.username}</p>
    ${authResult.user.email ? `<p><strong>Email:</strong> ${authResult.user.email}</p>` : ''}
    <p><a href="/auth/logout" class="btn" style="background: #dc3545;">Logout</a></p>
  </div>
  <div class="card">
    <h3>Endpoints</h3>
    <pre><code>SSE:      /sse
Messages: /messages
Health:   /health</code></pre>
  </div>`;
  } else {
    html += `
  <div class="card">
    <h2>🔐 Authentication Required</h2>
    <p>Please authenticate to access the MCP server.</p>
    <p><a href="/auth/login" class="btn">Login with ${provider.charAt(0).toUpperCase() + provider.slice(1)}</a></p>
  </div>`;
  }

  html += `
</body>
</html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

/**
 * Check authentication from cookie or Authorization header
 */
async function checkAuth(request: Request, env: Env): Promise<{ authorized: boolean; user?: UserSession; error?: string }> {
  // Check Authorization header first (Bearer token)
  const authHeader = request.headers.get('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    return verifySessionToken(token, env);
  }

  // Check cookie
  const cookie = request.headers.get('Cookie');
  if (cookie) {
    const match = cookie.match(/mcp_session=([^;]+)/);
    if (match) {
      return verifySessionToken(match[1], env);
    }
  }

  return { authorized: false, error: 'No authentication credentials provided' };
}

/**
 * Verify session token (JWT-like)
 */
async function verifySessionToken(token: string, env: Env): Promise<{ authorized: boolean; user?: UserSession; error?: string }> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { authorized: false, error: 'Invalid token format' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    
    // Verify signature
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.SESSION_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signature = Uint8Array.from(atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const data = encoder.encode(`${headerB64}.${payloadB64}`);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, data);
    if (!valid) {
      return { authorized: false, error: 'Invalid token signature' };
    }

    // Decode payload
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check expiration
    if (payload.exp && payload.exp < Date.now() / 1000) {
      return { authorized: false, error: 'Token expired' };
    }

    return { 
      authorized: true, 
      user: {
        userId: payload.sub,
        username: payload.username,
        email: payload.email,
        avatar: payload.avatar,
        provider: payload.provider,
        expiresAt: payload.exp * 1000
      }
    };
  } catch (error) {
    return { authorized: false, error: 'Token verification failed' };
  }
}

/**
 * Create session token
 */
async function createSessionToken(user: UserSession, env: Env): Promise<string> {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const payload = btoa(JSON.stringify({
    sub: user.userId,
    username: user.username,
    email: user.email,
    avatar: user.avatar,
    provider: user.provider,
    exp: Math.floor(user.expiresAt / 1000)
  })).replace(/=/g, '');

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(env.SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(`${header}.${payload}`));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '');

  return `${header}.${payload}.${signatureB64}`;
}

/**
 * Handle OAuth login initiation
 */
function handleOAuthLogin(_request: Request, env: Env): Response {
  const provider = env.OAUTH_PROVIDER || 'github';
  const state = crypto.randomUUID();
  
  let authUrl: string;
  let clientId = env.OAUTH_CLIENT_ID;
  let redirectUri = encodeURIComponent(env.OAUTH_REDIRECT_URI);

  switch (provider) {
    case 'github':
      authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&scope=user:email&state=${state}`;
      break;
    case 'google':
      authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=openid%20email%20profile&state=${state}`;
      break;
    case 'custom':
      if (!env.OAUTH_AUTH_URL) {
        return new Response('Custom OAuth provider requires OAUTH_AUTH_URL', { status: 500 });
      }
      authUrl = `${env.OAUTH_AUTH_URL}?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&state=${state}`;
      break;
    default:
      return new Response(`Unsupported OAuth provider: ${provider}`, { status: 500 });
  }

  // Store state in cookie for verification
  return new Response(null, {
    status: 302,
    headers: {
      'Location': authUrl,
      'Set-Cookie': `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
    }
  });
}

/**
 * Handle OAuth callback
 */
async function handleOAuthCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  
  // Verify state
  const cookie = request.headers.get('Cookie') || '';
  const stateMatch = cookie.match(/oauth_state=([^;]+)/);
  if (!stateMatch || stateMatch[1] !== state) {
    return new Response('Invalid OAuth state', { status: 400 });
  }

  if (!code) {
    return new Response('No authorization code provided', { status: 400 });
  }

  const provider = env.OAUTH_PROVIDER || 'github';

  try {
    // Exchange code for token
    let tokenUrl: string;
    let tokenBody: string;

    switch (provider) {
      case 'github':
        tokenUrl = 'https://github.com/login/oauth/access_token';
        tokenBody = `client_id=${env.OAUTH_CLIENT_ID}&client_secret=${env.OAUTH_CLIENT_SECRET}&code=${code}&redirect_uri=${encodeURIComponent(env.OAUTH_REDIRECT_URI)}`;
        break;
      case 'google':
        tokenUrl = 'https://oauth2.googleapis.com/token';
        tokenBody = `client_id=${env.OAUTH_CLIENT_ID}&client_secret=${env.OAUTH_CLIENT_SECRET}&code=${code}&redirect_uri=${encodeURIComponent(env.OAUTH_REDIRECT_URI)}&grant_type=authorization_code`;
        break;
      case 'custom':
        tokenUrl = env.OAUTH_TOKEN_URL!;
        tokenBody = `client_id=${env.OAUTH_CLIENT_ID}&client_secret=${env.OAUTH_CLIENT_SECRET}&code=${code}&redirect_uri=${encodeURIComponent(env.OAUTH_REDIRECT_URI)}&grant_type=authorization_code`;
        break;
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }

    const tokenResponse = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: tokenBody
    });

    const tokenData = await tokenResponse.json() as { error?: string; error_description?: string; access_token?: string };
    
    if (tokenData.error) {
      throw new Error(tokenData.error_description || tokenData.error);
    }

    const accessToken = tokenData.access_token;

    // Fetch user info
    let userUrl: string;
    let authHeader: string;

    switch (provider) {
      case 'github':
        userUrl = 'https://api.github.com/user';
        authHeader = `token ${accessToken}`;
        break;
      case 'google':
        userUrl = 'https://www.googleapis.com/oauth2/v2/userinfo';
        authHeader = `Bearer ${accessToken}`;
        break;
      case 'custom':
        userUrl = env.OAUTH_USER_URL!;
        authHeader = `Bearer ${accessToken}`;
        break;
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }

    const userResponse = await fetch(userUrl, {
      headers: { 'Authorization': authHeader }
    });

    const userData = await userResponse.json() as Record<string, any>;

    // Create user session
    let user: UserSession;
    
    switch (provider) {
      case 'github':
        user = {
          userId: String(userData.id),
          username: userData.login,
          email: userData.email,
          avatar: userData.avatar_url,
          provider: 'github',
          expiresAt: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
        };
        break;
      case 'google':
        user = {
          userId: userData.id,
          username: userData.name || userData.email,
          email: userData.email,
          avatar: userData.picture,
          provider: 'google',
          expiresAt: Date.now() + 24 * 60 * 60 * 1000
        };
        break;
      default:
        user = {
          userId: userData.id || userData.sub,
          username: userData.username || userData.name || userData.email,
          email: userData.email,
          avatar: userData.avatar || userData.picture,
          provider: 'custom',
          expiresAt: Date.now() + 24 * 60 * 60 * 1000
        };
    }

    // Create session token
    const sessionToken = await createSessionToken(user, env);

    // Redirect to home with session cookie
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': `mcp_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
      }
    });

  } catch (error) {
    console.error('OAuth callback error:', error);
    return new Response(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`, { status: 500 });
  }
}

/**
 * Handle logout
 */
function handleLogout(_request: Request, _env: Env): Response {
  return new Response(null, {
    status: 302,
    headers: {
      'Location': '/',
      'Set-Cookie': 'mcp_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'
    }
  });
}

/**
 * Handle auth me endpoint
 */
async function handleAuthMe(request: Request, env: Env): Promise<Response> {
  const authResult = await checkAuth(request, env);
  
  return new Response(JSON.stringify({
    authenticated: authResult.authorized,
    user: authResult.user || null,
    error: authResult.error || null
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * Handle SSE connection establishment
 * Returns endpoint URL for client to connect via POST
 */
function handleSSE(request: Request, user: UserSession): Response {
  const sessionId = crypto.randomUUID();
  
  const stream = new ReadableStream({
    start(controller) {
      // Send initial endpoint event
      const endpointMsg = `event: endpoint\ndata: /messages?sessionId=${sessionId}&userId=${user.userId}\n\n`;
      controller.enqueue(new TextEncoder().encode(endpointMsg));
      
      // Send keepalive every 30 seconds to prevent connection timeout
      const keepaliveInterval = setInterval(() => {
        try {
          const keepalive = `event: ping\ndata: {}\n\n`;
          controller.enqueue(new TextEncoder().encode(keepalive));
        } catch {
          clearInterval(keepaliveInterval);
        }
      }, 30000);

      // Cleanup on close
      request.signal.addEventListener('abort', () => {
        clearInterval(keepaliveInterval);
        controller.close();
      });
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * Handle JSON-RPC messages
 */
async function handleMessages(request: Request, env: Env, user: UserSession): Promise<Response> {
  // Only accept POST requests for JSON-RPC
  if (request.method !== 'POST') {
    return createErrorResponse(null, ErrorCode.INVALID_REQUEST, 'Only POST method is allowed for JSON-RPC messages', 405);
  }

  let body: JsonRpcRequest;
  try {
    body = await request.json();
  } catch (error) {
    return createErrorResponse(null, ErrorCode.PARSE_ERROR, `Invalid JSON: ${error instanceof Error ? error.message : 'Unknown error'}`, 400);
  }

  // Validate JSON-RPC structure
  if (body.jsonrpc !== JSONRPC_VERSION) {
    return createErrorResponse(body.id ?? null, ErrorCode.INVALID_REQUEST, `Invalid JSON-RPC version. Expected: ${JSONRPC_VERSION}`, 400);
  }

  if (!body.method || typeof body.method !== 'string') {
    return createErrorResponse(body.id ?? null, ErrorCode.INVALID_REQUEST, 'Missing or invalid method field', 400);
  }

  const { method, params, id } = body;
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('sessionId') ?? 'default';

  try {
    let result: any;

    switch (method) {
      case 'initialize':
        result = handleInitialize(params);
        break;

      case 'tools/list':
        result = { tools: TOOLS };
        break;

      case 'tools/call':
        result = await handleToolCall(params, sessionId, env, user);
        break;

      case 'ping':
        // Simple ping-pong for keepalive
        result = {};
        break;

      default:
        throw new McpError(ErrorCode.METHOD_NOT_FOUND, `Unknown method: ${method}`);
    }

    // Only return response if id is present (not a notification)
    if (id !== undefined) {
      return createSuccessResponse(id, result);
    }
    
    // For notifications, return 202 Accepted with no body per JSON-RPC spec
    return new Response(null, { status: 202 });

  } catch (error) {
    // Determine error code and message
    let code: number = ErrorCode.INTERNAL_ERROR;
    let message = 'Internal error';

    if (error instanceof McpError) {
      code = error.code;
      message = error.message;
    } else if (error instanceof Error) {
      message = error.message;
    }

    // Only include id in error response if it was present in request
    if (id !== undefined) {
      return createErrorResponse(id, code, message, 200); // JSON-RPC errors return 200 OK
    }
    
    // Notification errors are not returned to client per spec
    return new Response(null, { status: 202 });
  }
}

/**
 * Handle initialize request
 */
function handleInitialize(params: any): any {
  const clientProtocolVersion = params?.protocolVersion;
  
  // Supported protocol versions (latest first)
  const supportedVersions = ['2025-11-25', '2025-06-18', '2024-11-05'];
  
  // Protocol version negotiation - use client version if supported, otherwise use latest
  const protocolVersion = supportedVersions.includes(clientProtocolVersion) 
    ? clientProtocolVersion 
    : MCP_VERSION;
  
  return {
    protocolVersion,
    capabilities: { 
      tools: {},
      logging: {}
    },
    serverInfo: { 
      name: SERVER_NAME, 
      version: SERVER_VERSION 
    }
  };
}

/**
 * Handle tool call request
 */
async function handleToolCall(params: any, sessionId: string, env: Env, user: UserSession): Promise<any> {
  const toolName = params?.name;
  
  if (toolName !== 'sequentialthinking') {
    throw new McpError(ErrorCode.TOOL_NOT_FOUND, `Tool not found: ${toolName}`);
  }

  const args = params?.arguments ?? {};
  
  // Validate required parameters
  const required = ['thought', 'nextThoughtNeeded', 'thoughtNumber', 'totalThoughts', 'available_mcp_tools'];
  const missing = required.filter(field => !(field in args));
  
  if (missing.length > 0) {
    throw new McpError(
      ErrorCode.INVALID_TOOL_INPUT, 
      `Missing required parameters: ${missing.join(', ')}`
    );
  }

  // Type validation
  if (typeof args.thought !== 'string') {
    throw new McpError(ErrorCode.INVALID_TOOL_INPUT, 'Parameter "thought" must be a string');
  }
  if (typeof args.thoughtNumber !== 'number' || args.thoughtNumber < 1) {
    throw new McpError(ErrorCode.INVALID_TOOL_INPUT, 'Parameter "thoughtNumber" must be a positive number');
  }
  if (typeof args.totalThoughts !== 'number' || args.totalThoughts < 1) {
    throw new McpError(ErrorCode.INVALID_TOOL_INPUT, 'Parameter "totalThoughts" must be a positive number');
  }
  if (!Array.isArray(args.available_mcp_tools)) {
    throw new McpError(ErrorCode.INVALID_TOOL_INPUT, 'Parameter "available_mcp_tools" must be an array');
  }

  // Validate revision logic
  if (args.isRevision && !args.revisesThought) {
    throw new McpError(ErrorCode.INVALID_TOOL_INPUT, 'Parameter "revisesThought" is required when "isRevision" is true');
  }

  return await handleThinking(args, sessionId, env, user);
}

/**
 * Core thinking logic with KV persistence
 */
async function handleThinking(args: any, sessionId: string, env: Env, user: UserSession): Promise<any> {
  // Validate sessionId to prevent injection
  if (!/^[a-zA-Z0-9_-]+$/.test(sessionId)) {
    throw new McpError(ErrorCode.INVALID_PARAMS, 'Invalid sessionId format');
  }

  // Include user ID in key for user isolation
  const key = `session:${user.userId}:${sessionId}`;
  
  // Retrieve existing thoughts from KV with error handling
  let thoughts: Thought[] = [];
  try {
    const existing = await env.THINKING_KV.get(key);
    if (existing) {
      try {
        const parsed = JSON.parse(existing);
        if (Array.isArray(parsed)) {
          thoughts = parsed;
        }
      } catch (parseError) {
        // Log but don't fail - start fresh if data is corrupted
        console.error(`Failed to parse thoughts for session ${sessionId}:`, parseError);
      }
    }
  } catch (kvError) {
    console.error(`KV read error for session ${sessionId}:`, kvError);
    throw new McpError(ErrorCode.INTERNAL_ERROR, 'Failed to retrieve session data');
  }

  // Generate tool recommendations
  const recommendations = generateRecommendations(
    args.thought,
    args.available_mcp_tools || [],
    args.thoughtNumber,
    args.totalThoughts
  );

  // Calculate adjusted total thoughts
  const adjustedTotalThoughts = args.needsMoreThoughts 
    ? args.totalThoughts + 1 
    : args.totalThoughts;

  const newThought: Thought = {
    thought: args.thought,
    thoughtNumber: args.thoughtNumber,
    totalThoughts: adjustedTotalThoughts,
    nextThoughtNeeded: args.nextThoughtNeeded,
    isRevision: args.isRevision,
    revisesThought: args.revisesThought,
    branchFromThought: args.branchFromThought,
    branchId: args.branchId,
    needsMoreThoughts: args.needsMoreThoughts,
    toolRecommendations: recommendations,
    timestamp: Date.now()
  };

  // Handle revision or addition
  if (args.isRevision && args.revisesThought) {
    const idx = thoughts.findIndex(t => t.thoughtNumber === args.revisesThought);
    if (idx !== -1) {
      thoughts[idx] = newThought;
    } else {
      // If target thought not found, add as new but preserve revision metadata
      thoughts.push(newThought);
    }
  } else {
    thoughts.push(newThought);
  }

  // Sort by thought number
  thoughts.sort((a, b) => a.thoughtNumber - b.thoughtNumber);

  // Persist to KV with 1-hour TTL
  try {
    await env.THINKING_KV.put(key, JSON.stringify(thoughts), { expirationTtl: 3600 });
  } catch (kvError) {
    console.error(`KV write error for session ${sessionId}:`, kvError);
    throw new McpError(ErrorCode.INTERNAL_ERROR, 'Failed to save session data');
  }

  // Format output
  let output = `## Thought ${args.thoughtNumber}/${adjustedTotalThoughts}`;
  if (args.isRevision) output += ' (Revision)';
  if (args.branchId) output += ` [Branch: ${args.branchId}]`;
  output += `\n\n${args.thought}\n\n`;

  if (recommendations.length > 0) {
    output += `### Recommended Tools:\n`;
    recommendations.forEach((rec, i) => {
      output += `${i + 1}. **${rec.tool}** (${Math.round(rec.confidence * 100)}%) - ${rec.rationale}\n`;
    });
    output += '\n';
  }

  output += `---\nSession thoughts: ${thoughts.length}\nUser: ${user.username}`;

  return { 
    content: [{ type: 'text', text: output }] 
  };
}

/**
 * Generate tool recommendations based on thought content
 */
function generateRecommendations(
  thought: string,
  tools: string[],
  thoughtNum: number,
  totalThoughts: number
): ToolRecommendation[] {
  if (!tools.length) return [];

  const thoughtLower = thought.toLowerCase();
  const recs: ToolRecommendation[] = [];

  // Pattern matching for tool categories
  const patterns: Record<string, string[]> = {
    search: ['search', 'find', 'google', 'lookup', 'query', 'retrieve'],
    browser: ['web', 'page', 'click', 'navigate', 'http', 'url', 'website', 'browse'],
    file: ['file', 'read', 'write', 'folder', 'path', 'directory', 'save', 'load'],
    git: ['git', 'commit', 'push', 'pull', 'branch', 'merge', 'repository', 'repo'],
    api: ['api', 'endpoint', 'request', 'post', 'get', 'fetch', 'http', 'rest', 'graphql'],
    code: ['code', 'function', 'class', 'variable', 'debug', 'error', 'syntax'],
    db: ['database', 'sql', 'query', 'table', 'record', 'store', 'persist']
  };

  for (const tool of tools) {
    const toolLower = tool.toLowerCase();
    let confidence = 0;

    // Direct name match (remove common prefixes)
    const toolBaseName = toolLower.replace(/^(mcp-|server-)/g, '');
    if (thoughtLower.includes(toolBaseName)) {
      confidence += 0.4;
    }

    // Category pattern matching
    for (const [category, keywords] of Object.entries(patterns)) {
      if (toolLower.includes(category)) {
        const matches = keywords.filter(kw => thoughtLower.includes(kw));
        confidence += 0.3 * (matches.length / keywords.length);
      }
    }

    // Context boost for early thoughts
    if (thoughtNum === 1 && ['search', 'file', 'git'].some(x => toolLower.includes(x))) {
      confidence += 0.15;
    }

    // Context boost for final thoughts
    if (thoughtNum === totalThoughts && ['api', 'code', 'file'].some(x => toolLower.includes(x))) {
      confidence += 0.1;
    }

    if (confidence > 0.3) {
      recs.push({
        tool,
        confidence: Math.min(confidence, 0.95),
        rationale: `Matches patterns in thought context`,
        priority: confidence > 0.7 ? 'high' : (confidence > 0.5 ? 'medium' : 'low')
      });
    }
  }

  return recs.sort((a, b) => b.confidence - a.confidence).slice(0, 3);
}

/**
 * Create JSON-RPC success response
 */
function createSuccessResponse(id: string | number | null, result: any): Response {
  const response: JsonRpcResponse = {
    jsonrpc: JSONRPC_VERSION,
    id,
    result
  };

  return new Response(JSON.stringify(response), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * Create JSON-RPC error response
 */
function createErrorResponse(
  id: string | number | null | undefined, 
  code: number, 
  message: string, 
  httpStatus: number = 200
): Response {
  const response: JsonRpcResponse = {
    jsonrpc: JSONRPC_VERSION,
    error: {
      code,
      message
    }
  };

  // Only include id if it was provided (not undefined and not null from notification)
  if (id !== undefined && id !== null) {
    response.id = id;
  } else if (id === null) {
    // Explicit null id (invalid request) should include null id per JSON-RPC spec
    response.id = null;
  }

  return new Response(JSON.stringify(response), {
    status: httpStatus,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * MCP-specific error class for typed error handling
 */
class McpError extends Error {
  code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
    this.name = 'McpError';
  }
}
