import { describe, it, expect } from 'vitest'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import {
  auditMcpConfigJson,
  cliOption,
  createMcpServer,
  isSafeApiBaseUrl,
  isSafeTargetDomain,
  sanitizeUntrustedMcpText,
} from '../index.js'

const AGENT_ID = '5f0c2a8e-3b1d-4c6a-9e7f-2d4b6a8c0e1f'

interface RecordedCall {
  url: string
  method: string
  authorization: string | undefined
  body: string | undefined
}

async function connect(fetchImpl: typeof fetch, apiKey?: string, apiBaseUrl = 'https://api.example.test') {
  const server = createMcpServer({ apiBaseUrl, apiKey, fetchImpl })
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
  it('registers all four gateway and config audit tools', async () => {
    const client = await connect(async () => new Response('{}'))

    const { tools } = await client.listTools()

    expect(tools.map((tool) => tool.name).sort()).toEqual([
      'audit_mcp_config',
      'gateway_invoke',
      'gateway_resolve',
      'kya_status',
    ])
  })

  it('forwards gateway_resolve to the manifest route with the bearer key and returns the API body', async () => {
    const { fetchImpl, calls } = recordingFetch(
      () => new Response(JSON.stringify({ domain: 'shop.example', actions: [] }), { status: 200 })
    )
    const testKey = ['sk', 'live', 'test'].join('_')
    const client = await connect(fetchImpl, testKey)

    const result = await client.callTool({ name: 'gateway_resolve', arguments: { domain: 'shop.example' } })

    expect(result.isError).toBeFalsy()
    expect(JSON.parse(textOf(result))).toEqual({ domain: 'shop.example', actions: [] })
    expect(calls).toEqual([
      {
        url: 'https://api.example.test/v1/gateway/manifest/shop.example',
        method: 'GET',
        authorization: `Bearer ${testKey}`,
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

  it.each([
    '169.254.169.254',
    'http://127.0.0.1',
    'http://localhost:8080',
    'metadata.google.internal',
    '10.0.0.5',
    '192.168.1.10',
    '172.16.0.1',
    '0177.0.0.1',
    '0x7f000001',
    'file:///etc/passwd',
    '::1',
    'fd00:ec2::254',
  ])('blocks private or metadata target %j in gateway_resolve and gateway_invoke without calling fetch', async (domain) => {
    const { fetchImpl, calls } = recordingFetch(() => new Response('{}', { status: 200 }))
    const client = await connect(fetchImpl)

    const resolveRes = await client.callTool({ name: 'gateway_resolve', arguments: { domain } })
    expect(resolveRes.isError).toBe(true)
    expect(textOf(resolveRes)).toContain('Unsafe or private target domain blocked by MCP guard')

    const invokeRes = await client.callTool({
      name: 'gateway_invoke',
      arguments: { domain, action_id: 'buy', parameters: {} },
    })
    expect(invokeRes.isError).toBe(true)
    expect(textOf(invokeRes)).toContain('Unsafe or private target domain blocked by MCP guard')

    expect(calls).toEqual([])
  })

  it('validates apiBaseUrl scheme and blocks metadata apiBaseUrl', async () => {
    const { fetchImpl, calls } = recordingFetch(() => new Response('{}', { status: 200 }))

    const metadataClient = await connect(fetchImpl, undefined, 'http://169.254.169.254')
    const res1 = await metadataClient.callTool({ name: 'gateway_resolve', arguments: { domain: 'shop.example' } })
    expect(res1.isError).toBe(true)

    const httpExternalClient = await connect(fetchImpl, undefined, 'http://api.example.test')
    const res2 = await httpExternalClient.callTool({ name: 'gateway_resolve', arguments: { domain: 'shop.example' } })
    expect(res2.isError).toBe(true)

    expect(calls).toEqual([])
  })

  it('sends gateway_invoke as a POST with the domain, action slug and parameters', async () => {
    const answer = { action: 'reserve_ticket', upstream_status: 200, body: { reserved: 2 } }
    const { fetchImpl, calls } = recordingFetch(() => new Response(JSON.stringify(answer), { status: 200 }))
    const testKey = ['sk', 'live', 'test'].join('_')
    const client = await connect(fetchImpl, testKey)

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
        authorization: `Bearer ${testKey}`,
        body: JSON.stringify({ target_domain: 'shop.example', action_id: 'reserve_ticket', parameters: { seats: 2 } }),
      },
    ])
  })

  it('strips invisible and bidi Unicode characters from tool outputs and truncates long API errors', async () => {
    const dirtyBody = {
      note: 'clean\u200b\u202e\ufeff\u{E0001}text',
    }
    const { fetchImpl } = recordingFetch(() => new Response(JSON.stringify(dirtyBody), { status: 200 }))
    const client = await connect(fetchImpl)

    const res = await client.callTool({ name: 'gateway_resolve', arguments: { domain: 'shop.example' } })
    const outputText = textOf(res)
    expect(outputText).not.toMatch(/[\u200b\u202e\ufeff\u{E0001}]/u)
    expect(JSON.parse(outputText)).toEqual({ note: 'cleantext' })

    const longErrClient = await connect(async () => new Response('x'.repeat(1200), { status: 500 }))
    const errRes = await longErrClient.callTool({ name: 'gateway_resolve', arguments: { domain: 'shop.example' } })
    expect(errRes.isError).toBe(true)
    const errText = textOf(errRes)
    expect(errText.length).toBeLessThanOrEqual('gateway_resolve failed: '.length + 512)
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

  it('audits an insecure mcp.json locally via audit_mcp_config without network calls', async () => {
    const { fetchImpl, calls } = recordingFetch(() => new Response('{}'))
    const client = await connect(fetchImpl)

    const syntheticLeak = ['sk', 'live', 'fixture123456'].join('_')
    const insecureConfig = JSON.stringify({
      mcpServers: {
        leaky: {
          command: 'sh',
          args: ['-c', 'node --inspect server.js http://169.254.169.254/latest/meta-data/'],
          env: {
            STRIPE_KEY: syntheticLeak,
          },
          url: 'http://insecure.example.com/mcp',
        },
      },
    })

    const result = await client.callTool({
      name: 'audit_mcp_config',
      arguments: { config_json: insecureConfig },
    })

    expect(result.isError).toBeFalsy()
    expect(calls).toEqual([])
    const parsed = JSON.parse(textOf(result))
    expect(parsed.controlsAssessed).toBe(12)
    expect(parsed.failedCount).toBeGreaterThanOrEqual(4)
    expect(parsed.score).toBeLessThan(60)
    const byId = Object.fromEntries(parsed.controls.map((c: { id: string; status: string }) => [c.id, c.status]))
    expect(byId.stdio_isolation).toBe('fail')
    expect(byId.argument_ssrf_guard).toBe('fail')
    expect(byId.zero_plaintext_env_secrets).toBe('fail')
    expect(byId.egress_domain_allowlist).toBe('fail')
  })

  it('passes a hardened mcp.json in audit_mcp_config with score 100', async () => {
    const client = await connect(async () => new Response('{}'))

    const hardenedConfig = JSON.stringify({
      mcpServers: {
        stealthmark: {
          command: 'node',
          args: ['dist/index.js', '--api-url=https://api.stealthmark.io', '--audience=https://api.stealthmark.io/mcp'],
          env: {
            STEALTHMARK_API_KEY: '${STEALTHMARK_API_KEY}',
          },
          expectedAudience: 'https://api.stealthmark.io/mcp',
          scopes: ['gateway:read', 'kya:read'],
          schemaSha256: 'a'.repeat(64),
          blockPrivateNetworkUrls: true,
          hitl: true,
          maxSessionCalls: 50,
          sanitizeOutput: true,
          allowedDomains: ['api.stealthmark.io'],
          telemetry: { ecs: true, immutable: true },
          localOnly: true,
        },
      },
    })

    const result = await client.callTool({
      name: 'audit_mcp_config',
      arguments: { config_json: hardenedConfig },
    })

    expect(result.isError).toBeFalsy()
    const parsed = JSON.parse(textOf(result))
    expect(parsed.controlsAssessed).toBe(12)
    expect(parsed.passedCount).toBe(12)
    expect(parsed.warningCount).toBe(0)
    expect(parsed.failedCount).toBe(0)
    expect(parsed.score).toBe(100)
  })
})

describe('helper guards', () => {
  it('sanitizes NFKC and invisible bidi unicode', () => {
    expect(sanitizeUntrustedMcpText('ｈｅｌｌｏ\u200b\u202e\u{E0020}')).toBe('hello')
  })

  it('validates safe target domains and blocks IPv6-mapped, CGNAT, userinfo, and non-canonical SSRF vectors', () => {
    expect(isSafeTargetDomain('shop.example')).toBe(true)
    expect(isSafeTargetDomain('https://shop.example/a?b#c')).toBe(true)
    expect(isSafeTargetDomain('http://127.0.0.1')).toBe(false)
    expect(isSafeTargetDomain('169.254.169.254')).toBe(false)

    for (const blocked of [
      'http://[::ffff:127.0.0.1]',
      'http://[::ffff:7f00:1]',
      'http://[::ffff:a9fe:a9fe]',
      'http://[::127.0.0.1]',
      'http://[64:ff9b::127.0.0.1]',
      'http://[fd0::254]',
      'http://[fe8::1]',
      'http://100.100.100.200',
      'http://localhost.',
      'ｌｏｃａｌｈｏｓｔ',
      'http://user:pass@shop.example',
      'http://user:pass@127.0.0.1',
      'http://127.0.0.0x1',
      'http://2130706433',
      'http://2852039166',
      '//127.0.0.1/admin',
    ]) {
      expect(isSafeTargetDomain(blocked), blocked).toBe(false)
    }
  })

  it('validates isSafeApiBaseUrl against private HTTPS targets, IPv6-mapped metadata, non-canonical loopbacks, credentials, and query/hash', () => {
    expect(isSafeApiBaseUrl('https://api.example.test')).toBe(true)
    expect(isSafeApiBaseUrl('http://localhost:3001')).toBe(true)
    expect(isSafeApiBaseUrl('http://127.0.0.1:3001')).toBe(true)
    expect(isSafeApiBaseUrl('http://[::1]:3001')).toBe(true)
    expect(isSafeApiBaseUrl('https://localhost:3001')).toBe(true)

    for (const blocked of [
      'https://10.0.0.1',
      'https://192.168.1.1',
      'https://172.16.0.1',
      'https://100.100.100.200',
      'https://[::ffff:169.254.169.254]',
      'https://[::ffff:a9fe:a9fe]',
      'http://0177.0.0.1:3001',
      'http://0x7f000001:3001',
      'https://user:pass@api.example.test',
      'https://api.example.test/v1?x=1',
      'https://api.example.test#frag',
    ]) {
      expect(isSafeApiBaseUrl(blocked), blocked).toBe(false)
    }
  })

  it('prevents multi-server masking, boolean false passes, empty-server passes, and escaped invisible unicode in auditMcpConfigJson', () => {
    const maskedMulti = auditMcpConfigJson(
      JSON.stringify({
        mcpServers: {
          safe: {
            command: 'node',
            args: ['dist/index.js'],
            expectedAudience: 'https://api.stealthmark.io/mcp',
            hitl: true,
            allowedDomains: ['api.stealthmark.io'],
          },
          rogue: {
            command: 'node',
            args: ['rogue.js'],
            pkce: false,
            hitl: false,
            allowedDomains: ['10.0.0.1'],
          },
        },
      })
    )
    const maskedById = Object.fromEntries(maskedMulti.controls.map((c) => [c.id, c.status]))
    expect(maskedById.oauth_pkce_audience).toBe('fail')
    expect(maskedById.read_write_hitl_split).toBe('fail')
    expect(maskedById.egress_domain_allowlist).toBe('fail')

    const oauthFalse = auditMcpConfigJson(JSON.stringify({ oauth: false }))
    expect(oauthFalse.controls.find((c) => c.id === 'oauth_pkce_audience')?.status).toBe('fail')

    const emptyCollections = auditMcpConfigJson(
      JSON.stringify({
        mcpServers: { s: { command: 'node', args: ['a.js'] } },
        scopes: [],
        alwaysAllow: [],
        allowedDomains: [],
      })
    )
    const emptyColById = Object.fromEntries(emptyCollections.controls.map((c) => [c.id, c.status]))
    expect(emptyColById.delegated_obo_scope).toBe('warn')
    expect(emptyColById.read_write_hitl_split).toBe('warn')
    expect(emptyColById.egress_domain_allowlist).toBe('warn')

    const emptyServers = auditMcpConfigJson('{"mcpServers":{}}')
    expect(emptyServers.controlsAssessed).toBe(12)
    const emptyById = Object.fromEntries(emptyServers.controls.map((c) => [c.id, c.status]))
    expect(emptyById.stdio_isolation).toBe('warn')
    expect(emptyById.argument_ssrf_guard).toBe('warn')
    expect(emptyById.zero_plaintext_env_secrets).toBe('warn')
    expect(emptyById.web_surface_asphyxiation).toBe('warn')

    const escapedUnicodeJson = '{"mcpServers":{"s":{"command":"node","args":["a.js"],"note":"hi\\u200bthere"}}}'
    expect(
      auditMcpConfigJson(escapedUnicodeJson).controls.find((c) => c.id === 'output_prompt_sanitization')?.status
    ).toBe('fail')

    // Multi-server omission masking: srv1 hardened, srv2 omits required policies -> must NOT pass globally
    const partialMulti = auditMcpConfigJson(
      JSON.stringify({
        mcpServers: {
          hardened: {
            command: 'node',
            args: ['dist/index.js'],
            expectedAudience: 'https://api.stealthmark.io/mcp',
            scopes: ['gateway:read'],
            schemaSha256: 'a'.repeat(64),
            hitl: true,
            maxSessionCalls: 50,
            sanitizeOutput: true,
            allowedDomains: ['api.stealthmark.io'],
            telemetry: { ecs: true },
            localOnly: true,
          },
          unconfigured: {
            command: 'node',
            args: ['other.js'],
            url: 'https://remote.example.test/mcp',
          },
        },
      })
    )
    const partialById = Object.fromEntries(partialMulti.controls.map((c) => [c.id, c.status]))
    for (const id of [
      'oauth_pkce_audience',
      'delegated_obo_scope',
      'tool_schema_sha256_pin',
      'read_write_hitl_split',
      'session_budget_limit',
      'output_prompt_sanitization',
      'egress_domain_allowlist',
      'ecs_immutable_telemetry',
      'web_surface_asphyxiation',
    ]) {
      expect(partialById[id], id).toBe('warn')
    }

    // Expanded bind-all (0.0.0.0:port, --bind=0.0.0.0, [::]), forceAuthLocalhost, shell metacharacters, and expanded secret regexes
    for (const badBindCfg of [
      { mcpServers: { s: { command: 'node', args: ['srv.js', '--bind=0.0.0.0:8080'] } } },
      { mcpServers: { s: { command: 'node', args: ['srv.js', '--host', '[::]:9000'] } } },
      { mcpServers: { s: { command: 'node', args: ['srv.js', '--host', '::'] } } },
      { mcpServers: { s: { command: 'node', args: ['srv.js', 'http://0.0.0.0:3000'] } } },
      { mcpServers: { s: { command: 'node', args: ['srv.js', '--force-auth-localhost'] } } },
      { mcpServers: { s: { command: 'node', args: ['srv.js'], forceAuthLocalhost: true } } },
    ]) {
      const r = auditMcpConfigJson(JSON.stringify(badBindCfg))
      expect(r.controls.find((c) => c.id === 'web_surface_asphyxiation')?.status).toBe('fail')
    }

    const metacharRes = auditMcpConfigJson(
      JSON.stringify({ mcpServers: { s: { command: 'node', args: ['srv.js', '--name=$(id)'] } } })
    )
    expect(metacharRes.controls.find((c) => c.id === 'stdio_isolation')?.status).toBe('fail')

    // Anti-FP regression: snake_case words containing `re_` and `;charset=utf-8` headers must NOT false-positive
    const benignCfg = auditMcpConfigJson(
      JSON.stringify({
        mcpServers: {
          s: {
            command: 'node',
            args: [
              'srv.js',
              '--ignore_certificate_errors',
              '--header=Accept: text/plain;charset=utf-8',
            ],
            scopes: ['require_human_approval', 'azure_resource_management'],
            docs: 'https://docs.example.com/software_engineering_guide',
          },
        },
      })
    )
    expect(benignCfg.controls.find((c) => c.id === 'zero_plaintext_env_secrets')?.status).toBe('pass')
    expect(benignCfg.controls.find((c) => c.id === 'stdio_isolation')?.status).toBe('pass')

    const syntheticSecrets = [
      ['sk', 'proj', 'fixturetoken1234567890'].join('-'),
      ['sk', 'ant', 'fixturetoken1234567890'].join('-'),
      ['re', 'fixturetoken1234567890'].join('_'),
      ['rk', 'live', 'fixturetoken1234'].join('_'),
      `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url')}.${Buffer.from('{"sub":"1234567890"}').toString('base64url')}.signature123456`,
    ]
    for (const secret of syntheticSecrets) {
      const secRes = auditMcpConfigJson(
        JSON.stringify({ mcpServers: { s: { command: 'node', args: ['srv.js'], env: { TOKEN: secret } } } })
      )
      expect(secRes.controls.find((c) => c.id === 'zero_plaintext_env_secrets')?.status).toBe('fail')
    }
  })
})

describe('cliOption', () => {
  it('keeps every "=" after the first one in the value', () => {
    const argv = ['node', 'index.js', `--api-key=${['sk', 'live', 'abc=='].join('_')}`, '--api-url=https://api.example.test/v1?x=1']

    expect(cliOption(argv, 'api-key')).toBe(['sk', 'live', 'abc=='].join('_'))
    expect(cliOption(argv, 'api-url')).toBe('https://api.example.test/v1?x=1')
  })

  it('returns undefined when the option is missing, has no "=" or only shares a prefix', () => {
    expect(cliOption(['node', 'index.js'], 'api-key')).toBeUndefined()
    expect(cliOption(['node', 'index.js', '--api-key'], 'api-key')).toBeUndefined()
    expect(cliOption(['node', 'index.js', '--api-key-file=/tmp/key'], 'api-key')).toBeUndefined()
  })
})
