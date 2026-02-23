/**
 * MCP Sequential Thinking Server - Cloudflare Workers KV Edition
 * 
 * A Model Context Protocol (MCP) server implementation that provides structured,
 * step-by-step thinking for problem-solving with session persistence via Cloudflare KV.
 * 
 * Protocol: MCP 2024-11-05
 * Transport: HTTP + SSE (Server-Sent Events)
 * Runtime: Cloudflare Workers
 */

export interface Env {
  THINKING_KV: KVNamespace;
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

// MCP Protocol Constants
const MCP_VERSION = '2024-11-05';
const SERVER_NAME = 'sequential-thinking-kv';
const SERVER_VERSION = '1.0.0';
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

    // SSE endpoint for session establishment
    if (url.pathname === '/sse') {
      return handleSSE(request);
    }

    // JSON-RPC message endpoint
    if (url.pathname === '/messages') {
      return handleMessages(request, env);
    }

    // Health check endpoint
    if (url.pathname === '/health') {
      return new Response(
        JSON.stringify({ 
          status: 'ok', 
          server: SERVER_NAME,
          version: SERVER_VERSION,
          protocol: MCP_VERSION,
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

    // 404 for unknown paths
    return createErrorResponse(null, ErrorCode.METHOD_NOT_FOUND, `Path not found: ${url.pathname}`, 404);
  }
};

/**
 * Handle SSE connection establishment
 * Returns endpoint URL for client to connect via POST
 */
function handleSSE(request: Request): Response {
  const sessionId = crypto.randomUUID();
  
  const stream = new ReadableStream({
    start(controller) {
      // Send initial endpoint event
      const endpointMsg = `event: endpoint\ndata: /messages?sessionId=${sessionId}\n\n`;
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
async function handleMessages(request: Request, env: Env): Promise<Response> {
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
        result = await handleToolCall(params, sessionId, env);
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
    let code = ErrorCode.INTERNAL_ERROR;
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
  
  // Protocol version negotiation
  const protocolVersion = clientProtocolVersion === MCP_VERSION ? MCP_VERSION : '2024-11-05';
  
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
async function handleToolCall(params: any, sessionId: string, env: Env): Promise<any> {
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

  return await handleThinking(args, sessionId, env);
}

/**
 * Core thinking logic with KV persistence
 */
async function handleThinking(args: any, sessionId: string, env: Env): Promise<any> {
  // Validate sessionId to prevent injection
  if (!/^[a-zA-Z0-9_-]+$/.test(sessionId)) {
    throw new McpError(ErrorCode.INVALID_PARAMS, 'Invalid sessionId format');
  }

  const key = `session:${sessionId}`;
  
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

  output += `---\nSession thoughts: ${thoughts.length}`;

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
