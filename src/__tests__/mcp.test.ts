import { describe, it, expect } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { createMcpServer } from '../index.js'

interface RecordedCall {
  url: string
  method: string | undefined
  authorization: string | undefined
  body: string | undefined
}

async function connect(fetchImpl: typeof fetch, apiKey?: string) {
  const server = createMcpServer({ apiBaseUrl: 'https://api.example.test', apiKey, fetchImpl })
  const client = new Client({ name: 'test-client', version: '0.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return client
}

function recordingFetch(respond: () => Response): { fetchImpl: typeof fetch; calls: RecordedCall[] } {
  const calls: RecordedCall[] = []
  const fetchImpl: typeof fetch = async (input, init) => {
    const headers = new Headers(init?.headers)
    calls.push({
      url: String(input),
      method: init?.method,
      authorization: headers.get('authorization') ?? undefined,
      body: typeof init?.body === 'string' ? init.body : undefined,
    })
    return respond()
  }
  return { fetchImpl, calls }
}

function textOf(result: Awaited<ReturnType<Client['callTool']>>): string {
  const content = result.content
  if (!Array.isArray(content) || content.length === 0) throw new Error('tool returned no content')
  const first: unknown = content[0]
  if (typeof first !== 'object' || first === null || !('text' in first) || typeof first.text !== 'string') {
    throw new Error('tool returned a non-text block')
  }
  return first.text
}

describe('StealthMark MCP Server', () => {
  it('registers exactly the three gateway tools', async () => {
    const client = await connect(async () => new Response('{}'))

    const { tools } = await client.listTools()

    expect(tools.map((tool) => tool.name).sort()).toEqual(['gateway_invoke', 'gateway_resolve', 'kya_status'])
  })

  it('forwards gateway_resolve to the API with the bearer key and returns the API body', async () => {
    const { fetchImpl, calls } = recordingFetch(
      () => new Response(JSON.stringify({ domain: 'shop.example', actions: [] }), { status: 200 })
    )
    const client = await connect(fetchImpl, 'sk_live_test')

    const result = await client.callTool({ name: 'gateway_resolve', arguments: { domain: 'shop.example' } })

    expect(result.isError).toBeFalsy()
    expect(JSON.parse(textOf(result))).toEqual({ domain: 'shop.example', actions: [] })
    expect(calls).toEqual([
      {
        url: 'https://api.example.test/v1/gateway/resolve',
        method: 'POST',
        authorization: 'Bearer sk_live_test',
        body: JSON.stringify({ target_domain: 'shop.example' }),
      },
    ])
  })

  it('url-encodes the agent id for kya_status', async () => {
    const { fetchImpl, calls } = recordingFetch(() => new Response('{"status":"unknown"}', { status: 200 }))
    const client = await connect(fetchImpl)

    await client.callTool({ name: 'kya_status', arguments: { agent_id: 'a b/c' } })

    expect(calls[0].url).toBe('https://api.example.test/v1/kya/verify?agent_id=a%20b%2Fc')
    expect(calls[0].authorization).toBeUndefined()
  })

  it.each([
    { name: 'gateway_resolve', args: { domain: 'shop.example' } },
    { name: 'gateway_invoke', args: { domain: 'shop.example', action_id: 'buy', parameters: { sku: '1' } } },
    { name: 'kya_status', args: { agent_id: 'agent-1' } },
  ])('$name reports an API failure as an error and never invents a success payload', async ({ name, args }) => {
    const { fetchImpl } = recordingFetch(() => new Response('{"error":"not_found"}', { status: 404 }))
    const client = await connect(fetchImpl)

    const result = await client.callTool({ name, arguments: args })
    const text = textOf(result)

    expect(result.isError).toBe(true)
    expect(text).toContain(`${name} failed: StealthMark API error (404)`)
    expect(text).not.toMatch(/verified|success|executed|defcon/i)
  })

  it('reports a network failure as an error with the underlying message', async () => {
    const client = await connect(async () => {
      throw new TypeError('fetch failed')
    })

    const result = await client.callTool({ name: 'gateway_invoke', arguments: { domain: 'd.example', action_id: 'x', parameters: {} } })

    expect(result.isError).toBe(true)
    expect(textOf(result)).toBe('gateway_invoke failed: fetch failed')
  })
})
