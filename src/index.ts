#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'

/** Value of a `--name=value` option. Everything after the first `=` is the value, so keys and URLs that contain `=` survive. */
export function cliOption(argv: readonly string[], name: string): string | undefined {
  const prefix = `--${name}=`
  return argv.find((arg) => arg.startsWith(prefix))?.slice(prefix.length)
}

const cliApiKey = cliOption(process.argv, 'api-key')
const cliApiUrl = cliOption(process.argv, 'api-url')

const API_BASE_URL = cliApiUrl || process.env.STEALTHMARK_API_URL || 'http://localhost:3001'
const API_KEY = cliApiKey || process.env.STEALTHMARK_API_KEY

export interface McpServerOptions {
  apiBaseUrl?: string
  apiKey?: string
  fetchImpl?: typeof fetch
}

interface ToolResult {
  [key: string]: unknown
  content: Array<{ type: 'text'; text: string }>
  isError?: boolean
}

class StealthMarkApiError extends Error {
  constructor(readonly status: number, body: string) {
    super(`StealthMark API error (${status}): ${body}`)
    this.name = 'StealthMarkApiError'
  }
}

function textResult(value: unknown): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] }
}

function errorResult(tool: string, err: unknown): ToolResult {
  const message = err instanceof Error ? err.message : String(err)
  return { isError: true, content: [{ type: 'text', text: `${tool} failed: ${message}` }] }
}

export function createMcpServer(options: McpServerOptions = {}) {
  const apiBaseUrl = options.apiBaseUrl ?? API_BASE_URL
  const apiKey = options.apiKey ?? API_KEY
  const fetchImpl = options.fetchImpl ?? fetch

  const server = new McpServer({
    name: 'stealthmark',
    version: '0.1.0',
  })

  async function callApi(endpoint: string, init: RequestInit = {}): Promise<unknown> {
    const res = await fetchImpl(`${apiBaseUrl}${endpoint}`, {
      ...init,
      headers: {
        'Content-Type': 'application/json',
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
      },
    })

    if (!res.ok) {
      throw new StealthMarkApiError(res.status, await res.text())
    }

    return res.json()
  }

  server.tool(
    'gateway_resolve',
    "Resolve a website's machine-readable agent manifest and its exposed actions through the StealthMark API.",
    {
      // Same 3-character minimum as the API; it also keeps the '.' and '..' path segments out of the URL.
      domain: z.string().min(3).describe("Target website domain (e.g. 'intermiami.com')"),
    },
    async ({ domain }): Promise<ToolResult> => {
      try {
        return textResult(await callApi(`/v1/gateway/manifest/${encodeURIComponent(domain)}`))
      } catch (err: unknown) {
        return errorResult('gateway_resolve', err)
      }
    },
  )

  server.tool(
    'gateway_invoke',
    'Invoke an action a site declares in its agent manifest, through the StealthMark API.',
    {
      domain: z.string().describe('Target domain hosting the action'),
      action_id: z.string().describe("Action slug from the site's agent manifest (see gateway_resolve)"),
      parameters: z.record(z.string(), z.unknown()).describe("Parameters matching the action's inputSchema in the agent manifest"),
    },
    async ({ domain, action_id, parameters }): Promise<ToolResult> => {
      try {
        return textResult(
          await callApi('/v1/gateway/invoke', {
            method: 'POST',
            body: JSON.stringify({ target_domain: domain, action_id, parameters }),
          })
        )
      } catch (err: unknown) {
        return errorResult('gateway_invoke', err)
      }
    },
  )

  server.tool(
    'kya_status',
    "Look up one of your organization's registered agents (name, status, protocols) through the StealthMark API.",
    {
      agent_id: z.guid().describe('ID of the agent to look up'),
    },
    async ({ agent_id }): Promise<ToolResult> => {
      try {
        return textResult(await callApi(`/v1/agents/${encodeURIComponent(agent_id)}`))
      } catch (err: unknown) {
        return errorResult('kya_status', err)
      }
    },
  )

  return server
}

async function main() {
  const server = createMcpServer()
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error('StealthMark MCP Server running on stdio transport')
}

if (
  process.env.NODE_ENV !== 'test' &&
  (process.argv[1]?.endsWith('index.ts') ||
    process.argv[1]?.endsWith('index.js') ||
    process.argv[1]?.endsWith('stealthmark-mcp') ||
    process.argv[1]?.includes('mcp-server'))
) {
  main().catch((err) => {
    console.error('Fatal MCP Server error:', err)
    process.exit(1)
  })
}
