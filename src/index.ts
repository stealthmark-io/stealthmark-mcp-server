#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import {
  runMcpConfigAudit,
  type McpConfigAuditResult,
  type McpConfigControlFinding,
} from './audit-config.js'

export type { McpConfigAuditResult, McpConfigControlFinding }

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

const MAX_API_ERROR_MESSAGE_LENGTH = 512
const INVISIBLE_BIDI_CHARS =
  '\\u00ad\\u061c\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufe00-\\ufe0f\\ufeff\\u{E0000}-\\u{E007F}'
const INVISIBLE_BIDI_TEST_REGEX = new RegExp(`[${INVISIBLE_BIDI_CHARS}]`, 'u')
const INVISIBLE_BIDI_REPLACE_REGEX = new RegExp(`[${INVISIBLE_BIDI_CHARS}]`, 'gu')
const CONTROL_CHAR_REGEX = /[\x00-\x1f\x7f]/
const CANONICAL_DEC_OCTET_REGEX = /^(?:0|[1-9]\d{0,2})$/

/** Normalizes NFKC and strips invisible/bidi Unicode characters used for hidden prompt injection. */
export function sanitizeUntrustedMcpText(input: string): string {
  return input.normalize('NFKC').replace(INVISIBLE_BIDI_REPLACE_REGEX, '')
}

function normalizeHostLiteral(rawHost: string): string {
  return rawHost.normalize('NFKC').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '')
}

/** Detects pure decimal, pure hex, shorthand IPv4, or octal/hex segmented IP literals before URL resolution. */
export function isNonCanonicalIpLiteral(rawHost: string): boolean {
  const host = normalizeHostLiteral(rawHost)
  if (!host) return false
  if (/^\d+$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) {
    return true
  }
  const parts = host.split('.')
  if (parts.length < 1 || parts.length > 4) return false
  if (!parts.every((p) => /^(?:\d+|0x[0-9a-f]+)$/i.test(p))) return false
  if (parts.length < 4) return true
  return parts.some((p) => /^0\d+/.test(p) || /^0x[0-9a-f]+$/i.test(p))
}

/** Parses canonical dotted-decimal IPv4 (no leading zeros, octets 0..255). */
export function parseCanonicalIpv4(host: string): [number, number, number, number] | null {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const octets: number[] = []
  for (const part of parts) {
    if (!CANONICAL_DEC_OCTET_REGEX.test(part)) return null
    const n = Number(part)
    if (n > 255) return null
    octets.push(n)
  }
  return [octets[0]!, octets[1]!, octets[2]!, octets[3]!]
}

function isBlockedIpv4Octets([a, b, c]: [number, number, number, number]): boolean {
  if (a === 0 || a === 10 || a === 127 || a >= 224) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  return false
}

function parseIpv6SegmentList(segmentStr: string): number[] | null {
  if (!segmentStr) return []
  const tokens = segmentStr.split(':')
  const groups: number[] = []
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!
    if (!tok) return null
    if (tok.includes('.')) {
      if (i !== tokens.length - 1) return null
      const ipv4 = parseCanonicalIpv4(tok)
      if (!ipv4) return null
      groups.push((ipv4[0] << 8) | ipv4[1], (ipv4[2] << 8) | ipv4[3])
    } else if (/^[0-9a-f]{1,4}$/i.test(tok)) {
      groups.push(parseInt(tok, 16))
    } else {
      return null
    }
  }
  return groups
}

/** Expands an IPv6 literal (with optional `::` compression or embedded IPv4) into 8 canonical 16-bit groups. */
export function parseIpv6Groups(rawHost: string): number[] | null {
  const withoutZone = rawHost.split('%')[0] ?? ''
  if (!withoutZone.includes(':')) return null
  const halves = withoutZone.split('::')
  if (halves.length > 2) return null

  const left = parseIpv6SegmentList(halves[0] ?? '')
  if (!left) return null

  if (halves.length === 1) {
    return left.length === 8 ? left : null
  }

  const right = parseIpv6SegmentList(halves[1] ?? '')
  if (!right) return null
  const totalExplicit = left.length + right.length
  if (totalExplicit > 7) return null
  return [...left, ...new Array<number>(8 - totalExplicit).fill(0), ...right]
}

function isBlockedIpv6Groups(g: number[]): boolean {
  const allZeroPrefix5 = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0
  if (allZeroPrefix5 && g[5] === 0 && g[6] === 0 && (g[7] === 0 || g[7] === 1)) {
    return true
  }
  if ((g[0]! & 0xfe00) === 0xfc00 || (g[0]! & 0xffc0) === 0xfe80 || (g[0]! & 0xff00) === 0xff00) {
    return true
  }
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true

  const isIpv4Mapped = allZeroPrefix5 && g[5] === 0xffff
  const isIpv4Compat = allZeroPrefix5 && g[5] === 0 && (g[6] !== 0 || g[7] !== 0)
  const isNat64 = g[0] === 0x0064 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0
  if (isIpv4Mapped || isIpv4Compat || isNat64) {
    const octets: [number, number, number, number] = [
      (g[6]! >> 8) & 0xff,
      g[6]! & 0xff,
      (g[7]! >> 8) & 0xff,
      g[7]! & 0xff,
    ]
    return isBlockedIpv4Octets(octets)
  }

  // Only IANA Global Unicast (2000::/3) is externally routable; blocks non-routable prefixes (e.g. 0fd0::, 0fe8::).
  return (g[0]! & 0xe000) !== 0x2000
}

function isBlockedSpecialHostname(host: string): boolean {
  if (
    host === 'localhost' ||
    host === 'localhost.localdomain' ||
    host === 'metadata' ||
    host === 'metadata.google.internal' ||
    host === 'instance-data'
  ) {
    return true
  }
  return (
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.arpa') ||
    host.endsWith('.invalid')
  )
}

function isBlockedIpOrHostname(rawHostname: string): boolean {
  const host = normalizeHostLiteral(rawHostname)
  if (!host || host.includes('@') || /\s/.test(host) || host.includes('..')) {
    return true
  }
  if (isBlockedSpecialHostname(host) || isNonCanonicalIpLiteral(host)) {
    return true
  }
  const ipv4 = parseCanonicalIpv4(host)
  if (ipv4) {
    return isBlockedIpv4Octets(ipv4)
  }
  if (host.includes(':')) {
    const ipv6 = parseIpv6Groups(host)
    return ipv6 ? isBlockedIpv6Groups(ipv6) : true
  }
  return false
}

function extractRawHostSegment(rawUrlOrDomain: string): string {
  const withoutScheme = rawUrlOrDomain.replace(/^https?:\/\//i, '')
  const authority = withoutScheme.split(/[/?#]/)[0] ?? ''
  if (authority.startsWith('[')) {
    const endBracket = authority.indexOf(']')
    return endBracket >= 0 ? authority.slice(0, endBracket + 1) : authority
  }
  const colonCount = authority.match(/:/g)?.length ?? 0
  return colonCount === 1 ? (authority.split(':')[0] ?? '') : authority
}

/** Validates that a target domain/URL is public and does not point to localhost, RFC1918, metadata, or non-canonical IPs. */
export function isSafeTargetDomain(rawDomain: string): boolean {
  if (typeof rawDomain !== 'string') return false
  const normalized = rawDomain.normalize('NFKC').trim()
  if (
    normalized.length < 3 ||
    /\s/.test(normalized) ||
    normalized.includes('..') ||
    normalized.includes('@') ||
    CONTROL_CHAR_REGEX.test(normalized) ||
    normalized.startsWith('//')
  ) {
    return false
  }
  if (normalized.includes('://') && !/^https?:\/\//i.test(normalized)) {
    return false
  }

  const rawHostSegment = extractRawHostSegment(normalized)
  if (isNonCanonicalIpLiteral(rawHostSegment) || isBlockedIpOrHostname(rawHostSegment)) {
    return false
  }

  let parsed: URL
  try {
    parsed = new URL(normalized.includes('://') ? normalized : `https://${normalized}`)
  } catch {
    return false
  }

  if (parsed.username !== '' || parsed.password !== '') return false
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false
  return !isBlockedIpOrHostname(parsed.hostname)
}

/** Validates that a StealthMark API base URL uses HTTPS (or explicit canonical loopback) and has no private/non-canonical host or credentials. */
export function isSafeApiBaseUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== 'string') return false
  const normalized = rawUrl.normalize('NFKC').trim()
  if (!normalized || normalized.includes('@') || /\s/.test(normalized) || CONTROL_CHAR_REGEX.test(normalized)) {
    return false
  }
  const schemeMatch = /^(https?):\/\//i.exec(normalized)
  if (!schemeMatch) return false

  const afterScheme = normalized.slice(schemeMatch[0].length)
  const authority = afterScheme.split(/[/?#]/)[0] ?? ''
  let rawHost = authority
  if (authority.startsWith('[')) {
    const endBracket = authority.indexOf(']')
    if (endBracket < 0) return false
    rawHost = authority.slice(0, endBracket + 1)
  } else if ((authority.match(/:/g)?.length ?? 0) === 1) {
    rawHost = authority.split(':')[0] ?? ''
  }

  const rawHostNoDots = rawHost.toLowerCase().replace(/\.+$/, '')
  if (!rawHostNoDots || isNonCanonicalIpLiteral(rawHostNoDots)) return false

  let parsed: URL
  try {
    parsed = new URL(normalized)
  } catch {
    return false
  }

  if (parsed.username !== '' || parsed.password !== '' || parsed.search !== '' || parsed.hash !== '') {
    return false
  }

  const isCanonicalLoopback =
    rawHostNoDots === 'localhost' || rawHostNoDots === '127.0.0.1' || rawHostNoDots === '[::1]'
  if (parsed.protocol === 'http:') {
    return isCanonicalLoopback
  }
  if (parsed.protocol === 'https:') {
    return isCanonicalLoopback || !isBlockedIpOrHostname(parsed.hostname)
  }
  return false
}

function validateApiBaseUrl(rawBaseUrl: string): void {
  if (!isSafeApiBaseUrl(rawBaseUrl)) {
    throw new Error('Unsafe or invalid StealthMark API base URL blocked')
  }
}

/** Deterministically evaluates an mcp.json configuration against the 12 MCP security controls without network calls. */
export function auditMcpConfigJson(rawConfigJson: string): McpConfigAuditResult {
  return runMcpConfigAudit(rawConfigJson, {
    isSafeTargetDomain,
    isBlockedIpOrHostname,
    isNonCanonicalIpLiteral,
    extractRawHostSegment,
    invisibleBidiTestRegex: INVISIBLE_BIDI_TEST_REGEX,
  })
}

class StealthMarkApiError extends Error {
  constructor(readonly status: number, body: string) {
    const cleanBody = sanitizeUntrustedMcpText(body)
    const full = `StealthMark API error (${status}): ${cleanBody}`
    const truncated =
      full.length > MAX_API_ERROR_MESSAGE_LENGTH
        ? `${full.slice(0, MAX_API_ERROR_MESSAGE_LENGTH - 3)}...`
        : full
    super(truncated)
    this.name = 'StealthMarkApiError'
  }
}

function textResult(value: unknown): ToolResult {
  return { content: [{ type: 'text', text: sanitizeUntrustedMcpText(JSON.stringify(value, null, 2)) }] }
}

function errorResult(tool: string, err: unknown): ToolResult {
  const rawMessage = err instanceof Error ? err.message : String(err)
  const message = sanitizeUntrustedMcpText(rawMessage)
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
    validateApiBaseUrl(apiBaseUrl)
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
        if (!isSafeTargetDomain(domain)) {
          throw new Error('Unsafe or private target domain blocked by MCP guard')
        }
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
        if (!isSafeTargetDomain(domain)) {
          throw new Error('Unsafe or private target domain blocked by MCP guard')
        }
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

  server.tool(
    'audit_mcp_config',
    'Audit a local mcp.json / .cursor/mcp.json configuration deterministically against the 12 MCP security controls without making network calls.',
    {
      config_json: z
        .string()
        .min(2)
        .describe('Raw JSON content of an mcp.json / .cursor/mcp.json configuration to audit locally against the 12 MCP security controls'),
    },
    async ({ config_json }): Promise<ToolResult> => {
      try {
        return textResult(auditMcpConfigJson(config_json))
      } catch (err: unknown) {
        return errorResult('audit_mcp_config', err)
      }
    },
  )

  return server
}

async function main() {
  if (cliApiKey) {
    console.error('[stealthmark-mcp] WARNING: Passing --api-key via CLI arguments exposes credentials in process listings (ps). Use STEALTHMARK_API_KEY env var instead.')
  }
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
