import { describe, it, expect } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { cliOption, createMcpServer } from '../index.js'

const AGENT_ID = '5f0c2a8e-3b1d-4c6a-9e7f-2d4b6a8c0e1f'

interface RecordedCall {
  url: string
  method: string
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
      method: init?.method ?? 'GET',
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

  it('forwards gateway_resolve to the manifest route with the bearer key and returns the API body', async () => {
    const { fetchImpl, calls } = recordingFetch(
      () => new Response(JSON.stringify({ domain: 'shop.example', actions: [] }), { status: 200 })
    )
    const client = await connect(fetchImpl, 'sk_live_test')

    const result = await client.callTool({ name: 'gateway_resolve', arguments: { domain: 'shop.example' } })

    expect(result.isError).toBeFalsy()
    expect(JSON.parse(textOf(result))).toEqual({ domain: 'shop.example', actions: [] })
    expect(calls).toEqual([
      {
        url: 'https://api.example.test/v1/gateway/manifest/shop.example',
        method: 'GET',
        authorization: 'Bearer sk_live_test',
        body: undefined,
      },
    ])
  })

  it('url-encodes the domain for gateway_resolve', async () => {
    const { fetchImpl, calls } = recordingFetch(() => new Response('{}', { status: 200 }))
    const client = await connect(fetchImpl)

    await client.callTool({ name: 'gateway_resolve', arguments: { domain: 'https://shop.example/a?b#c' } })

    expect(calls.map((call) => call.url)).toEqual([
      'https://api.example.test/v1/gateway/manifest/https%3A%2F%2Fshop.example%2Fa%3Fb%23c',
    ])
  })

  it.each(['', '.', '..'])('rejects the domain %j for gateway_resolve without calling the API', async (domain) => {
    const { fetchImpl, calls } = recordingFetch(() => new Response('{}', { status: 200 }))
    const client = await connect(fetchImpl)

    const result = await client.callTool({ name: 'gateway_resolve', arguments: { domain } })

    expect(result.isError).toBe(true)
    expect(calls).toEqual([])
  })

  it('sends gateway_invoke as a POST with the domain, action slug and parameters', async () => {
    const answer = { action: 'reserve_ticket', upstream_status: 200, body: { reserved: 2 } }
    const { fetchImpl, calls } = recordingFetch(() => new Response(JSON.stringify(answer), { status: 200 }))
    const client = await connect(fetchImpl, 'sk_live_test')

    const result = await client.callTool({
      name: 'gateway_invoke',
      arguments: { domain: 'shop.example', action_id: 'reserve_ticket', parameters: { seats: 2 } },
    })

    expect(result.isError).toBeFalsy()
    expect(JSON.parse(textOf(result))).toEqual(answer)
    expect(calls).toEqual([
      {
        url: 'https://api.example.test/v1/gateway/invoke',
        method: 'POST',
        authorization: 'Bearer sk_live_test',
        body: JSON.stringify({ target_domain: 'shop.example', action_id: 'reserve_ticket', parameters: { seats: 2 } }),
      },
    ])
  })

  it('looks up the agent by id for kya_status', async () => {
    const { fetchImpl, calls } = recordingFetch(() => new Response(JSON.stringify({ id: AGENT_ID }), { status: 200 }))
    const client = await connect(fetchImpl)

    const result = await client.callTool({ name: 'kya_status', arguments: { agent_id: AGENT_ID } })

    expect(result.isError).toBeFalsy()
    expect(JSON.parse(textOf(result))).toEqual({ id: AGENT_ID })
    expect(calls).toEqual([
      { url: `https://api.example.test/v1/agents/${AGENT_ID}`, method: 'GET', authorization: undefined, body: undefined },
    ])
  })

  it.each([{}, { agent_id: '' }, { agent_id: '.' }, { agent_id: '..' }, { agent_id: 'a b/c' }, { agent_id: 'agent-1' }])(
    'rejects the kya_status arguments %j without calling the API',
    async (args) => {
      const { fetchImpl, calls } = recordingFetch(() => new Response('{}', { status: 200 }))
      const client = await connect(fetchImpl)

      const result = await client.callTool({ name: 'kya_status', arguments: args })

      expect(result.isError).toBe(true)
      expect(calls).toEqual([])
    }
  )

  it.each([
    { name: 'gateway_resolve', args: { domain: 'shop.example' } },
    { name: 'gateway_invoke', args: { domain: 'shop.example', action_id: 'buy', parameters: { sku: '1' } } },
    { name: 'kya_status', args: { agent_id: AGENT_ID } },
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

describe('cliOption', () => {
  it('keeps every "=" after the first one in the value', () => {
    const argv = ['node', 'index.js', '--api-key=sk_live_abc==', '--api-url=https://api.example.test/v1?x=1']

    expect(cliOption(argv, 'api-key')).toBe('sk_live_abc==')
    expect(cliOption(argv, 'api-url')).toBe('https://api.example.test/v1?x=1')
  })

  it('returns undefined when the option is missing, has no "=" or only shares a prefix', () => {
    expect(cliOption(['node', 'index.js'], 'api-key')).toBeUndefined()
    expect(cliOption(['node', 'index.js', '--api-key'], 'api-key')).toBeUndefined()
    expect(cliOption(['node', 'index.js', '--api-key-file=/tmp/key'], 'api-key')).toBeUndefined()
  })
})
