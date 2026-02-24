/**
 * MCP Sequential Thinking Server - Cloudflare Workers with MCP OAuth 2.0
 * 
 * Implements MCP 2025-11-25 specification with OAuth 2.0 authorization.
 * 
 * Protocol: MCP 2025-11-25
 * Transport: HTTP + SSE (Server-Sent Events)
 * Auth: OAuth 2.0 (RFC 9728 Protected Resource Metadata)
 */

export interface Env {
  THINKING_KV?: KVNamespace;
  // OAuth configuration
  OAUTH_ISSUER: string;  // e.g., https://your-worker.workers.dev
  // For JWT signing
  JWT_SECRET: string;
}

// In-memory storage fallback (for development without KV)
const memoryStore = new Map<string, { value: string; expires?: number }>();

async function kvGet(env: Env, key: string): Promise<string | null> {
  if (env.THINKING_KV) {
    return await kvGet(env, key);
  }
  const item = memoryStore.get(key);
  if (!item) return null;
  if (item.expires && item.expires < Date.now()) {
    memoryStore.delete(key);
    return null;
  }
  return item.value;
}

async function kvPut(env: Env, key: string, value: string, options?: { expirationTtl?: number }): Promise<void> {
  if (env.THINKING_KV) {
    await kvPut(env, key, value, options);
    return;
  }
  memoryStore.set(key, {
    value,
    expires: options?.expirationTtl ? Date.now() + options.expirationTtl * 1000 : undefined
  });
}

async function kvDelete(env: Env, key: string): Promise<void> {
  if (env.THINKING_KV) {
    await kvDelete(env, key);
    return;
  }
  memoryStore.delete(key);
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
  sessionId: string;
}

interface ToolRecommendation {
  tool: string;
  confidence: number;
  rationale: string;
  priority: 'high' | 'medium' | 'low';
}

// OAuth client registration
interface OAuthClient {
  client_id: string;
  client_secret?: string;
  redirect_uris: string[];
  client_name?: string;
  grant_types: string[];
  response_types: string[];
  scope?: string;
}

// Access token payload
interface AccessTokenPayload {
  sub: string;  // client_id
  scope: string;
  iat: number;
  exp: number;
}

// MCP Protocol Constants
const MCP_VERSION = '2025-11-25';
const SERVER_NAME = 'sequential-thinking-oauth';
const SERVER_VERSION = '1.0.0';
const JSONRPC_VERSION = '2.0';

// OAuth scopes
const SCOPES = ['mcp:tools', 'mcp:resources', 'mcp:prompts'];

// JSON-RPC Error Codes
const ErrorCode = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  TOOL_NOT_FOUND: -32000,
  INVALID_TOOL_INPUT: -32005,
  UNAUTHORIZED: -32001,
} as const;

// Tool definitions
const TOOLS = [
  {
    name: 'sequentialthinking',
    description: 'Facilitates a detailed, step-by-step thinking process for problem-solving and analysis.',
    inputSchema: {
      type: 'object',
      properties: {
        thought: { type: 'string', description: 'The current thinking step content' },
        nextThoughtNeeded: { type: 'boolean', description: 'Whether another thought step is needed' },
        thoughtNumber: { type: 'number', description: 'Current thought number (1-indexed)' },
        totalThoughts: { type: 'number', description: 'Estimated total thoughts needed' },
        available_mcp_tools: { type: 'array', items: { type: 'string' }, description: 'List of available MCP tool names' },
        isRevision: { type: 'boolean', description: 'Whether this revises previous thinking' },
        revisesThought: { type: 'number', description: 'Which thought number is being reconsidered' },
        branchFromThought: { type: 'number', description: 'Branching point thought number' },
        branchId: { type: 'string', description: 'Branch identifier string' },
        needsMoreThoughts: { type: 'boolean', description: 'If more thoughts are needed beyond current estimate' }
      },
      required: ['thought', 'nextThoughtNeeded', 'thoughtNumber', 'totalThoughts', 'available_mcp_tools'],
      additionalProperties: false
    }
  }
];

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
  error?: { code: number; message: string; data?: any; };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // CORS preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400'
          }
        });
      }

    // OAuth 2.0 Protected Resource Metadata (RFC 9728)
    if (path === '/.well-known/oauth-protected-resource') {
      return handleProtectedResourceMetadata(env);
    }

    // OAuth 2.0 Authorization Server Metadata
    if (path === '/.well-known/oauth-authorization-server') {
      return handleAuthorizationServerMetadata(env);
    }

    // OAuth Dynamic Client Registration (RFC 7591)
    if (path === '/oauth/register' && request.method === 'POST') {
      return handleClientRegistration(request, env);
    }

    // OAuth Authorize endpoint
    if (path === '/oauth/authorize' && request.method === 'GET') {
      return handleAuthorize(request, env);
    }

    // OAuth Token endpoint
    if (path === '/oauth/token' && request.method === 'POST') {
      return handleToken(request, env);
    }

    // OAuth JWK Set for token verification
    if (path === '/oauth/jwks') {
      return handleJWKS(env);
    }

    // Health check (no auth required)
    if (path === '/health') {
      // Test KV
      let kvStatus = 'not_configured';
      try {
        if (env.THINKING_KV) {
          await env.THINKING_KV.put('test:key', 'ok', { expirationTtl: 60 });
          const val = await env.THINKING_KV.get('test:key');
          kvStatus = val === 'ok' ? 'ok' : 'error';
        }
      } catch (e) {
        kvStatus = 'error: ' + (e instanceof Error ? e.message : 'unknown');
      }
      
      return new Response(JSON.stringify({
        status: 'ok',
        server: SERVER_NAME,
        version: SERVER_VERSION,
        protocol: MCP_VERSION,
        auth: 'oauth-2.0',
        kv: kvStatus,
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
    
    // Debug endpoint
    if (path === '/debug' && request.method === 'POST') {
      const body = await request.json();
      return new Response(JSON.stringify({ received: body }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    // SSE endpoint
    if (path === '/sse') {
      const authResult = await verifyAuth(request, env);
      if (!authResult.valid) {
        return new Response(JSON.stringify({ error: 'unauthorized', error_description: authResult.error }), {
          status: 401,
          headers: { 
            'Content-Type': 'application/json',
            'WWW-Authenticate': 'Bearer error="invalid_token"'
          }
        });
      }
      return handleSSE(request, authResult.clientId!);
    }

    // JSON-RPC messages endpoint
    if (path === '/messages') {
      const authResult = await verifyAuth(request, env);
      if (!authResult.valid) {
        return createErrorResponse(null, ErrorCode.UNAUTHORIZED, authResult.error || 'Unauthorized', 401);
      }
      return handleMessages(request, env, authResult.clientId!);
    }

    // Root - show info
    if (path === '/') {
      return new Response(JSON.stringify({
        name: SERVER_NAME,
        version: SERVER_VERSION,
        protocol: MCP_VERSION,
        authorization: `${env.OAUTH_ISSUER}/.well-known/oauth-protected-resource`
      }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }

    return createErrorResponse(null, ErrorCode.METHOD_NOT_FOUND, `Path not found: ${path}`, 404);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return new Response(JSON.stringify({ error: 'internal_error', message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
  }
};

/**
 * OAuth 2.0 Protected Resource Metadata (RFC 9728)
 */
function handleProtectedResourceMetadata(env: Env): Response {
  const metadata = {
    resource: env.OAUTH_ISSUER,
    authorization_servers: [env.OAUTH_ISSUER],
    scopes_supported: SCOPES,
    bearer_methods_supported: ['header'],
    resource_documentation: `${env.OAUTH_ISSUER}/health`
  };
  
  return new Response(JSON.stringify(metadata), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * OAuth 2.0 Authorization Server Metadata
 */
function handleAuthorizationServerMetadata(env: Env): Response {
  const metadata = {
    issuer: env.OAUTH_ISSUER,
    authorization_endpoint: `${env.OAUTH_ISSUER}/oauth/authorize`,
    token_endpoint: `${env.OAUTH_ISSUER}/oauth/token`,
    registration_endpoint: `${env.OAUTH_ISSUER}/oauth/register`,
    jwks_uri: `${env.OAUTH_ISSUER}/oauth/jwks`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'client_credentials'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: SCOPES,
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    introspection_endpoint: `${env.OAUTH_ISSUER}/oauth/introspect`,
    revocation_endpoint: `${env.OAUTH_ISSUER}/oauth/revoke`
  };
  
  return new Response(JSON.stringify(metadata), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/**
 * OAuth Dynamic Client Registration (RFC 7591)
 */
async function handleClientRegistration(request: Request, env: Env): Promise<Response> {
  let body: Record<string, any>;
  try {
    body = await request.json() as Record<string, any>;
  } catch {
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'Invalid JSON' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Generate client credentials
  const clientId = crypto.randomUUID();
  const clientSecret = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
  
  const client: OAuthClient = {
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: body.redirect_uris || [],
    client_name: body.client_name || 'MCP Client',
    grant_types: body.grant_types || ['authorization_code', 'client_credentials'],
    response_types: body.response_types || ['code'],
    scope: body.scope || SCOPES.join(' ')
  };

  // Store client in KV
  await kvPut(env, `oauth:client:${clientId}`, JSON.stringify(client), { expirationTtl: 86400 * 365 });

  const response = {
    client_id: client.client_id,
    client_secret: client.client_secret,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_secret_expires_at: 0, // Never expires
    redirect_uris: client.redirect_uris,
    client_name: client.client_name,
    grant_types: client.grant_types,
    response_types: client.response_types,
    scope: client.scope
  };

  return new Response(JSON.stringify(response), {
    status: 201,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

/**
 * OAuth Authorize endpoint - for user consent flow
 */
async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get('client_id');
  const redirectUri = url.searchParams.get('redirect_uri');
  const scope = url.searchParams.get('scope') || '';
  const state = url.searchParams.get('state') || '';
  const codeChallenge = url.searchParams.get('code_challenge');
  const codeChallengeMethod = url.searchParams.get('code_challenge_method') || 'S256';

  if (!clientId || !redirectUri) {
    return new Response(JSON.stringify({ error: 'invalid_request', error_description: 'Missing required parameters' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Verify client exists
  const clientData = await kvGet(env, `oauth:client:${clientId}`);
  if (!clientData) {
    return new Response(JSON.stringify({ error: 'invalid_client', error_description: 'Client not found' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // For automated clients, auto-approve and redirect with code
  const authCode = crypto.randomUUID();
  
  // Store auth code with PKCE challenge
  await kvPut(env, `oauth:code:${authCode}`, JSON.stringify({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: scope,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    expires_at: Date.now() + 60000 // 1 minute
  }), { expirationTtl: 60 });

  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set('code', authCode);
  if (state) redirectUrl.searchParams.set('state', state);

  return new Response(null, {
    status: 302,
    headers: { Location: redirectUrl.toString() }
  });
}

/**
 * OAuth Token endpoint
 */
async function handleToken(request: Request, env: Env): Promise<Response> {
  const contentType = request.headers.get('Content-Type') || '';
  let body: Record<string, string>;

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const text = await request.text();
    body = Object.fromEntries(new URLSearchParams(text));
  } else {
    body = await request.json();
  }

  const grantType = body.grant_type;

  if (grantType === 'client_credentials') {
    return handleClientCredentialsGrant(body, env);
  } else if (grantType === 'authorization_code') {
    return handleAuthorizationCodeGrant(body, env);
  }

  return new Response(JSON.stringify({ error: 'unsupported_grant_type', error_description: `Grant type ${grantType} not supported` }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' }
  });
}

/**
 * Client Credentials Grant
 */
async function handleClientCredentialsGrant(body: Record<string, string>, env: Env): Promise<Response> {
  const clientId = body.client_id;
  const clientSecret = body.client_secret;
  const scope = body.scope || SCOPES.join(' ');

  // Verify client credentials
  const clientData = await kvGet(env, `oauth:client:${clientId}`);
  if (!clientData) {
    return new Response(JSON.stringify({ error: 'invalid_client' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const client = JSON.parse(clientData) as OAuthClient;
  if (client.client_secret !== clientSecret) {
    return new Response(JSON.stringify({ error: 'invalid_client' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Generate access token
  const accessToken = await generateJWT(clientId, scope, env);

  return new Response(JSON.stringify({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: scope
  }), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

/**
 * Authorization Code Grant
 */
async function handleAuthorizationCodeGrant(body: Record<string, string>, env: Env): Promise<Response> {
  const code = body.code;
  const clientId = body.client_id;
  const redirectUri = body.redirect_uri;
  const codeVerifier = body.code_verifier;

  // Get stored auth code
  const codeData = await kvGet(env, `oauth:code:${code}`);
  if (!codeData) {
    return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const authCode = JSON.parse(codeData);

  // Verify client
  if (authCode.client_id !== clientId) {
    return new Response(JSON.stringify({ error: 'invalid_client' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Verify redirect URI
  if (authCode.redirect_uri !== redirectUri) {
    return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Verify PKCE code verifier
  if (authCode.code_challenge) {
    const encoder = new TextEncoder();
    const verifierData = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest('SHA-256', verifierData);
    const hashBase64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    if (hashBase64 !== authCode.code_challenge) {
      return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'PKCE verification failed' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }

  // Delete used auth code
  await kvDelete(env, `oauth:code:${code}`);

  // Generate access token
  const accessToken = await generateJWT(clientId, authCode.scope, env);

  return new Response(JSON.stringify({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: authCode.scope
  }), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

/**
 * JWKS endpoint for token verification
 */
async function handleJWKS(env: Env): Promise<Response> {
  // For HMAC keys, we use the raw key bytes directly
  const keyBytes = new TextEncoder().encode(env.JWT_SECRET).slice(0, 32);
  const k = btoa(String.fromCharCode(...keyBytes)).replace(/=/g, '');

  const jwks = {
    keys: [{
      kty: 'oct',
      kid: 'mcp-key-1',
      use: 'sig',
      alg: 'HS256',
      k: k
    }]
  };

  return new Response(JSON.stringify(jwks), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

/**
 * Generate JWT access token
 */
async function generateJWT(clientId: string, scope: string, env: Env): Promise<string> {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '');
  const payload = btoa(JSON.stringify({
    sub: clientId,
    scope: scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  })).replace(/=/g, '');

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(env.JWT_SECRET).slice(0, 32),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(`${header}.${payload}`));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '');

  return `${header}.${payload}.${signatureB64}`;
}

/**
 * Verify JWT access token
 */
async function verifyJWT(token: string, env: Env): Promise<{ valid: boolean; payload?: AccessTokenPayload; error?: string }> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid token format' };
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(env.JWT_SECRET).slice(0, 32),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signature = Uint8Array.from(atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const data = encoder.encode(`${headerB64}.${payloadB64}`);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, data);
    if (!valid) {
      return { valid: false, error: 'Invalid signature' };
    }

    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as AccessTokenPayload;
    
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, error: 'Token expired' };
    }

    return { valid: true, payload };
  } catch (error) {
    return { valid: false, error: 'Token verification failed' };
  }
}

/**
 * Verify Authorization header
 */
async function verifyAuth(request: Request, env: Env): Promise<{ valid: boolean; clientId?: string; error?: string }> {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return { valid: false, error: 'Missing Authorization header' };
  }

  if (!authHeader.startsWith('Bearer ')) {
    return { valid: false, error: 'Invalid Authorization header format' };
  }

  const token = authHeader.slice(7);
  const result = await verifyJWT(token, env);

  if (!result.valid) {
    return { valid: false, error: result.error };
  }

  return { valid: true, clientId: result.payload!.sub };
}

/**
 * Handle SSE connection
 */
function handleSSE(request: Request, _clientId: string): Response {
  const sessionId = crypto.randomUUID();
  
  const stream = new ReadableStream({
    start(controller) {
      const endpointMsg = `event: endpoint\ndata: /messages?sessionId=${sessionId}\n\n`;
      controller.enqueue(new TextEncoder().encode(endpointMsg));
      
      const keepaliveInterval = setInterval(() => {
        try {
          controller.enqueue(new TextEncoder().encode(`event: ping\ndata: {}\n\n`));
        } catch {
          clearInterval(keepaliveInterval);
        }
      }, 30000);

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
async function handleMessages(request: Request, env: Env, clientId: string): Promise<Response> {
  if (request.method !== 'POST') {
    return createErrorResponse(null, ErrorCode.INVALID_REQUEST, 'Only POST method allowed', 405);
  }

  let body: JsonRpcRequest;
  try {
    body = await request.json();
  } catch (error) {
    return createErrorResponse(null, ErrorCode.PARSE_ERROR, 'Invalid JSON', 400);
  }

  if (body.jsonrpc !== JSONRPC_VERSION) {
    return createErrorResponse(body.id ?? null, ErrorCode.INVALID_REQUEST, 'Invalid JSON-RPC version', 400);
  }

  if (!body.method || typeof body.method !== 'string') {
    return createErrorResponse(body.id ?? null, ErrorCode.INVALID_REQUEST, 'Missing method', 400);
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
        result = await handleToolCall(params, sessionId, env, clientId);
        break;
      case 'ping':
        result = {};
        break;
      default:
        throw new McpError(ErrorCode.METHOD_NOT_FOUND, `Unknown method: ${method}`);
    }

    if (id !== undefined) {
      return createSuccessResponse(id, result);
    }
    return new Response(null, { status: 202 });
  } catch (error) {
    let code: number = ErrorCode.INTERNAL_ERROR;
    let message = 'Internal error';

    if (error instanceof McpError) {
      code = error.code;
      message = error.message;
    } else if (error instanceof Error) {
      message = error.message;
    }

    if (id !== undefined) {
      return createErrorResponse(id, code, message, 200);
    }
    return new Response(null, { status: 202 });
  }
}

/**
 * Handle initialize request
 */
function handleInitialize(params: any): any {
  const clientProtocolVersion = params?.protocolVersion;
  const supportedVersions = ['2025-11-25', '2025-06-18', '2024-11-05'];
  const protocolVersion = supportedVersions.includes(clientProtocolVersion) ? clientProtocolVersion : MCP_VERSION;
  
  return {
    protocolVersion,
    capabilities: { tools: {}, logging: {} },
    serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }
  };
}

/**
 * Handle tool call
 */
async function handleToolCall(params: any, sessionId: string, env: Env, clientId: string): Promise<any> {
  const toolName = params?.name;
  
  if (toolName !== 'sequentialthinking') {
    throw new McpError(ErrorCode.TOOL_NOT_FOUND, `Tool not found: ${toolName}`);
  }

  const args = params?.arguments ?? {};
  const required = ['thought', 'nextThoughtNeeded', 'thoughtNumber', 'totalThoughts', 'available_mcp_tools'];
  const missing = required.filter(field => !(field in args));
  
  if (missing.length > 0) {
    throw new McpError(ErrorCode.INVALID_TOOL_INPUT, `Missing required parameters: ${missing.join(', ')}`);
  }

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

  return await handleThinking(args, sessionId, env, clientId);
}

/**
 * Core thinking logic
 */
async function handleThinking(args: any, sessionId: string, env: Env, clientId: string): Promise<any> {
  if (!/^[a-zA-Z0-9_-]+$/.test(sessionId)) {
    throw new McpError(ErrorCode.INVALID_PARAMS, 'Invalid sessionId format');
  }

  const key = `thoughts:${clientId}:${sessionId}`;
  
  let thoughts: Thought[] = [];
  const existing = await kvGet(env, key);
  if (existing) {
    try {
      thoughts = JSON.parse(existing);
    } catch {}
  }

  const recommendations = generateRecommendations(args.thought, args.available_mcp_tools || [], args.thoughtNumber, args.totalThoughts);
  const adjustedTotalThoughts = args.needsMoreThoughts ? args.totalThoughts + 1 : args.totalThoughts;

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
    timestamp: Date.now(),
    sessionId
  };

  if (args.isRevision && args.revisesThought) {
    const idx = thoughts.findIndex(t => t.thoughtNumber === args.revisesThought);
    if (idx !== -1) {
      thoughts[idx] = newThought;
    } else {
      thoughts.push(newThought);
    }
  } else {
    thoughts.push(newThought);
  }

  thoughts.sort((a, b) => a.thoughtNumber - b.thoughtNumber);
  await kvPut(env, key, JSON.stringify(thoughts), { expirationTtl: 3600 });

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

  output += `---\nSession thoughts: ${thoughts.length}`;

  return { content: [{ type: 'text', text: output }] };
}

/**
 * Generate tool recommendations
 */
function generateRecommendations(thought: string, tools: string[], _thoughtNum: number, _totalThoughts: number): ToolRecommendation[] {
  if (!tools.length) return [];

  const thoughtLower = thought.toLowerCase();
  const recs: ToolRecommendation[] = [];

  const patterns: Record<string, string[]> = {
    search: ['search', 'find', 'google', 'lookup', 'query'],
    browser: ['web', 'page', 'click', 'navigate', 'url'],
    file: ['file', 'read', 'write', 'folder', 'path'],
    git: ['git', 'commit', 'push', 'pull', 'branch'],
    api: ['api', 'endpoint', 'request', 'fetch'],
    code: ['code', 'function', 'class', 'debug']
  };

  for (const tool of tools) {
    const toolLower = tool.toLowerCase();
    let confidence = 0;

    const toolBaseName = toolLower.replace(/^(mcp-|server-)/g, '');
    if (thoughtLower.includes(toolBaseName)) {
      confidence += 0.4;
    }

    for (const [category, keywords] of Object.entries(patterns)) {
      if (toolLower.includes(category)) {
        const matches = keywords.filter(kw => thoughtLower.includes(kw));
        confidence += 0.3 * (matches.length / keywords.length);
      }
    }

    if (confidence > 0.3) {
      recs.push({
        tool,
        confidence: Math.min(confidence, 0.95),
        rationale: 'Matches patterns in thought context',
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
  return new Response(JSON.stringify({ jsonrpc: JSONRPC_VERSION, id, result }), {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

/**
 * Create JSON-RPC error response
 */
function createErrorResponse(id: string | number | null | undefined, code: number, message: string, httpStatus: number = 200): Response {
  const response: JsonRpcResponse = {
    jsonrpc: JSONRPC_VERSION,
    error: { code, message }
  };
  if (id !== undefined && id !== null) response.id = id;
  else if (id === null) response.id = null;

  return new Response(JSON.stringify(response), {
    status: httpStatus,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

/**
 * MCP Error class
 */
class McpError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
    this.name = 'McpError';
  }
}
