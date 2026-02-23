// 纯 KV 版 - 无需 wrangler.toml，支持 GitHub Actions 部署
export interface Env {
  THINKING_KV: KVNamespace;  // 绑定 KV 命名空间
}

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
  toolRecommendations?: any[];
  timestamp: number;
}

const MCP_VERSION = '2024-11-05';
const SERVER_NAME = 'sequential-thinking-kv';
const SERVER_VERSION = '1.0.0';

const TOOLS = [
  {
    name: 'sequentialthinking',
    description: 'Break down problems into sequential thoughts with tool recommendations',
    inputSchema: {
      type: 'object',
      properties: {
        thought: { type: 'string' },
        nextThoughtNeeded: { type: 'boolean' },
        thoughtNumber: { type: 'number' },
        totalThoughts: { type: 'number' },
        available_mcp_tools: { type: 'array', items: { type: 'string' } },
        isRevision: { type: 'boolean' },
        revisesThought: { type: 'number' },
        branchFromThought: { type: 'number' },
        branchId: { type: 'string' },
        needsMoreThoughts: { type: 'boolean' }
      },
      required: ['thought', 'nextThoughtNeeded', 'thoughtNumber', 'totalThoughts', 'available_mcp_tools']
    }
  }
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type'
        }
      });
    }

    // SSE 端点
    if (url.pathname === '/sse') {
      const sessionId = crypto.randomUUID();
      const stream = new ReadableStream({
        start(controller) {
          const msg = `event: endpoint\ndata: /messages?sessionId=${sessionId}\n\n`;
          controller.enqueue(new TextEncoder().encode(msg));
        }
      });
      return new Response(stream, {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache'
        }
      });
    }

    // JSON-RPC 消息
    if (url.pathname === '/messages') {
      const body = await request.json();
      const { method, params, id } = body;
      const sessionId = url.searchParams.get('sessionId') || 'default';
      
      let result: any;

      try {
        switch (method) {
          case 'initialize':
            result = {
              protocolVersion: MCP_VERSION,
              capabilities: { tools: {} },
              serverInfo: { name: SERVER_NAME, version: SERVER_VERSION }
            };
            break;
            
          case 'tools/list':
            result = { tools: TOOLS };
            break;
            
          case 'tools/call':
            if (params.name === 'sequentialthinking') {
              result = await handleThinking(params.arguments, sessionId, env);
            } else {
              throw new Error('Unknown tool');
            }
            break;
            
          default:
            result = {};
        }

        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), {
          headers: { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
        
      } catch (error) {
        return new Response(JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32000, message: String(error) }
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // 健康检查
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};

async function handleThinking(args: any, sessionId: string, env: Env): Promise<any> {
  // 从 KV 读取历史
  const key = `session:${sessionId}`;
  const existing = await env.THINKING_KV.get(key);
  let thoughts: Thought[] = existing ? JSON.parse(existing) : [];
  
  // 生成工具推荐
  const recommendations = generateRecommendations(
    args.thought,
    args.available_mcp_tools || [],
    args.thoughtNumber,
    args.totalThoughts
  );

  const newThought: Thought = {
    thought: args.thought,
    thoughtNumber: args.thoughtNumber,
    totalThoughts: args.needsMoreThoughts ? args.totalThoughts + 1 : args.totalThoughts,
    nextThoughtNeeded: args.nextThoughtNeeded,
    isRevision: args.isRevision,
    revisesThought: args.revisesThought,
    branchFromThought: args.branchFromThought,
    branchId: args.branchId,
    needsMoreThoughts: args.needsMoreThoughts,
    toolRecommendations: recommendations,
    timestamp: Date.now()
  };

  // 更新历史
  if (args.isRevision && args.revisesThought) {
    const idx = thoughts.findIndex(t => t.thoughtNumber === args.revisesThought);
    if (idx !== -1) thoughts[idx] = newThought;
    else thoughts.push(newThought);
  } else {
    thoughts.push(newThought);
  }
  
  thoughts.sort((a, b) => a.thoughtNumber - b.thoughtNumber);

  // 保存到 KV（1小时过期，自动清理）
  await env.THINKING_KV.put(key, JSON.stringify(thoughts), { expirationTtl: 3600 });

  // 格式化输出
  let output = `## Thought ${args.thoughtNumber}/${newThought.totalThoughts}`;
  if (args.isRevision) output += ' (Revision)';
  if (args.branchId) output += ` [Branch: ${args.branchId}]`;
  output += `\n\n${args.thought}\n\n`;

  if (recommendations.length > 0) {
    output += `### Recommended Tools:\n`;
    recommendations.forEach((rec, i) => {
      output += `${i+1}. **${rec.tool}** (${Math.round(rec.confidence*100)}%) - ${rec.rationale}\n`;
    });
    output += '\n';
  }

  output += `---\nSession thoughts: ${thoughts.length}`;

  return { content: [{ type: 'text', text: output }] };
}

function generateRecommendations(
  thought: string,
  tools: string[],
  thoughtNum: number,
  totalThoughts: number
): any[] {
  if (!tools.length) return [];
  
  const thoughtLower = thought.toLowerCase();
  const recs: any[] = [];
  
  const patterns: Record<string, string[]> = {
    'search': ['search', 'find', 'google', 'lookup'],
    'browser': ['web', 'page', 'click', 'navigate', 'http'],
    'file': ['file', 'read', 'write', 'folder', 'path'],
    'git': ['git', 'commit', 'push', 'pull', 'branch'],
    'api': ['api', 'endpoint', 'request', 'post', 'get']
  };

  for (const tool of tools) {
    const toolLower = tool.toLowerCase();
    let confidence = 0;
    
    if (thoughtLower.includes(toolLower.replace(/mcp-|server-/g, ''))) {
      confidence += 0.4;
    }
    
    for (const [cat, pats] of Object.entries(patterns)) {
      if (toolLower.includes(cat)) {
        const matches = pats.filter(p => thoughtLower.includes(p));
        confidence += 0.3 * (matches.length / pats.length);
      }
    }
    
    if (thoughtNum === 1 && ['search','file'].some(x => toolLower.includes(x))) confidence += 0.2;
    
    if (confidence > 0.3) {
      recs.push({
        tool,
        confidence: Math.min(confidence, 0.95),
        rationale: `Matches patterns in thought`,
        priority: confidence > 0.7 ? 'high' : 'medium'
      });
    }
  }
  
  return recs.sort((a, b) => b.confidence - a.confidence).slice(0, 3);
}
