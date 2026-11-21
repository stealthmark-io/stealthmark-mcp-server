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

export interface McpConfigControlFinding {
  id: string
  status: 'pass' | 'warn' | 'fail'
  detail: string
}

export interface McpConfigAuditResult {
  score: number
  controlsAssessed: 12
  passedCount: number
  warningCount: number
  failedCount: number
  serverNames: string[]
  controls: McpConfigControlFinding[]
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
const PLAINTEXT_SECRET_REGEX =
  /(?:sk_live_[A-Za-z0-9_-]+|ghp_[A-Za-z0-9]+|gho_[A-Za-z0-9]+|AIza[0-9A-Za-z_-]+|AKIA[0-9A-Z]{16}|xoxb-[0-9A-Za-z-]+|xoxp-[0-9A-Za-z-]+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i
const SHELL_COMMAND_REGEX = /(?:^|[\\/])(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i
const SHELL_EXEC_ARG_REGEX = /\b(?:sh|bash|zsh)\s+-c\b|\bcmd(?:\.exe)?\s+\/c\b|\bpowershell(?:\.exe)?\s+-c\b/i
const INSPECT_FLAG_REGEX = /--inspect(?:-brk)?(?:=|\b)/i
const BIND_ALL_REGEX = /(?:--host(?:=|\s+)|--listen(?:=|\s+))0\.0\.0\.0\b/i
const HTTP_URL_REGEX = /(?:https?:\/\/|(?<=^|[\s"'`=(])\/\/)[^\s"'`<>]+/gi
const NON_HTTP_SSRF_PROBE_REGEX = /(?:file:\/\/|169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|fd00:ec2::254)/i
const WILDCARD_SCOPE_REGEX = /^(?:\*|admin:\*|root|full_access|superuser)$/i

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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function collectStrings(value: unknown, out: string[]): void {
  if (typeof value === 'string') {
    out.push(value)
    return
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out)
    return
  }
  if (isPlainObject(value)) {
    for (const v of Object.values(value)) collectStrings(v, out)
  }
}

function isLoopbackHttpUrl(urlStr: string): boolean {
  try {
    const rawHost = extractRawHostSegment(urlStr.normalize('NFKC').trim()).toLowerCase().replace(/\.+$/, '')
    if (rawHost !== 'localhost' && rawHost !== '127.0.0.1' && rawHost !== '[::1]') {
      return false
    }
    const parsed = new URL(urlStr)
    return parsed.protocol === 'http:'
  } catch {
    return false
  }
}

function collectValues(objects: Record<string, unknown>[], keys: string[]): unknown[] {
  const values: unknown[] = []
  for (const obj of objects) {
    for (const key of keys) {
      if (key in obj && obj[key] !== undefined) {
        values.push(obj[key])
      }
    }
  }
  return values
}

function hasBooleanFlag(objects: Record<string, unknown>[], keys: string[], target: boolean): boolean {
  return collectValues(objects, keys).some((v) => v === target)
}

function isPositiveEvidence(value: unknown): boolean {
  if (value === true) return true
  if (typeof value === 'number') return Number.isFinite(value) && value > 0
  if (typeof value === 'string') return value.trim().length > 0
  if (Array.isArray(value)) return value.length > 0
  if (isPlainObject(value)) return Object.keys(value).length > 0
  return false
}

function isSsrfUrlCandidate(urlStr: string): boolean {
  const normalized = urlStr.normalize('NFKC').trim()
  if (NON_HTTP_SSRF_PROBE_REGEX.test(normalized)) return true
  const rawHost = extractRawHostSegment(normalized.replace(/^\/\//, ''))
  if (isNonCanonicalIpLiteral(rawHost)) return true
  try {
    const parsed = new URL(normalized.startsWith('//') ? `http:${normalized}` : normalized)
    if (parsed.username !== '' || parsed.password !== '') return true
    const cleanRaw = rawHost.toLowerCase().replace(/\.+$/, '')
    if (cleanRaw === 'localhost' || cleanRaw === '127.0.0.1' || cleanRaw === '[::1]') {
      return false
    }
    return isBlockedIpOrHostname(parsed.hostname)
  } catch {
    return rawHost.length > 0 && isBlockedIpOrHostname(rawHost)
  }
}

interface ExtractedMcpSignals {
  serverNames: string[]
  serverEntries: Record<string, unknown>[]
  allObjects: Record<string, unknown>[]
  allStrings: string[]
  envAndArgStrings: string[]
  urlStrings: string[]
  hasShellInvocation: boolean
  hasInspectFlag: boolean
  hasPrivilegedStdio: boolean
  hasPlaintextSecret: boolean
  hasSsrfUrl: boolean
  hasNonLoopbackHttp: boolean
  hasInvisibleUnicode: boolean
}

function extractServerMap(parsed: Record<string, unknown>): Record<string, Record<string, unknown>> {
  const serversMap: Record<string, Record<string, unknown>> = {}
  for (const containerKey of ['mcpServers', 'servers']) {
    const container = parsed[containerKey]
    if (isPlainObject(container)) {
      for (const [name, cfg] of Object.entries(container)) {
        if (isPlainObject(cfg)) serversMap[name] = cfg
      }
    }
  }
  return serversMap
}

function isPlaintextBearerHeader(headers: unknown): boolean {
  if (!isPlainObject(headers)) return false
  return Object.values(headers).some(
    (v) => typeof v === 'string' && /^bearer\s+(?!\$\{)(?!\$[A-Z0-9_]+)(?!<)[A-Za-z0-9._-]{12,}$/i.test(v.trim())
  )
}

function extractMcpSignals(parsed: Record<string, unknown>, rawConfigJson: string): ExtractedMcpSignals {
  const serversMap = extractServerMap(parsed)
  const serverNames = Object.keys(serversMap)
  const serverEntries = Object.values(serversMap)
  const topSecurity = isPlainObject(parsed.security) ? [parsed.security] : []
  const topPolicy = isPlainObject(parsed.policy) ? [parsed.policy] : []
  const allObjects: Record<string, unknown>[] = [...serverEntries, ...topSecurity, ...topPolicy, parsed]

  const allStrings: string[] = []
  collectStrings(parsed, allStrings)

  const envAndArgStrings: string[] = []
  const urlStrings: string[] = []
  let hasShellInvocation = false
  let hasInspectFlag = false
  let hasPrivilegedStdio = false

  for (const srv of serverEntries) {
    const cmd = typeof srv.command === 'string' ? srv.command.trim() : ''
    const args = Array.isArray(srv.args) ? srv.args.filter((a): a is string => typeof a === 'string') : []
    const joined = [cmd, ...args].join(' ').trim()

    if (SHELL_COMMAND_REGEX.test(cmd) || SHELL_EXEC_ARG_REGEX.test(joined)) hasShellInvocation = true
    if (INSPECT_FLAG_REGEX.test(joined)) hasInspectFlag = true
    if (srv.privileged === true || srv.sandbox === false) hasPrivilegedStdio = true

    if (isPlainObject(srv.env)) {
      collectStrings(srv.env, envAndArgStrings)
      if (typeof srv.env.NODE_OPTIONS === 'string' && INSPECT_FLAG_REGEX.test(srv.env.NODE_OPTIONS)) {
        hasInspectFlag = true
      }
    }
    if (isPlainObject(srv.headers)) collectStrings(srv.headers, envAndArgStrings)
    envAndArgStrings.push(...args)
    if (typeof srv.url === 'string') urlStrings.push(srv.url)
  }

  for (const s of allStrings) {
    const matches = s.match(HTTP_URL_REGEX)
    if (matches) urlStrings.push(...matches)
    if (NON_HTTP_SSRF_PROBE_REGEX.test(s)) urlStrings.push(s)
  }

  const hasInvisibleUnicode =
    INVISIBLE_BIDI_TEST_REGEX.test(rawConfigJson) || allStrings.some((s) => INVISIBLE_BIDI_TEST_REGEX.test(s))
  const hasPlaintextSecret =
    envAndArgStrings.some((s) => PLAINTEXT_SECRET_REGEX.test(s)) ||
    allStrings.some((s) => PLAINTEXT_SECRET_REGEX.test(s)) ||
    serverEntries.some((srv) => isPlaintextBearerHeader(srv.headers))
  const hasSsrfUrl = urlStrings.some(isSsrfUrlCandidate)
  const hasNonLoopbackHttp = urlStrings.some((u) => /^http:\/\//i.test(u) && !isLoopbackHttpUrl(u))

  return {
    serverNames,
    serverEntries,
    allObjects,
    allStrings,
    envAndArgStrings,
    urlStrings,
    hasShellInvocation,
    hasInspectFlag,
    hasPrivilegedStdio,
    hasPlaintextSecret,
    hasSsrfUrl,
    hasNonLoopbackHttp,
    hasInvisibleUnicode,
  }
}

function evalStdioIsolation(sig: ExtractedMcpSignals): McpConfigControlFinding {
  if (sig.hasShellInvocation || sig.hasInspectFlag || sig.hasPrivilegedStdio) {
    return {
      id: 'stdio_isolation',
      status: 'fail',
      detail: 'Detected shell wrapper (sh/bash -c), debugger (--inspect), or unisolated privileged stdio flag.',
    }
  }
  if (sig.serverEntries.length === 0) {
    return { id: 'stdio_isolation', status: 'warn', detail: 'No MCP servers declared in configuration.' }
  }
  return {
    id: 'stdio_isolation',
    status: 'pass',
    detail: 'Direct binary/runtime invocation without shell wrappers or debugger flags.',
  }
}

function evalOauthPkceAudience(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const disabled =
    hasBooleanFlag(sig.allObjects, ['insecureSkipVerify'], true) ||
    hasBooleanFlag(sig.allObjects, ['pkce', 'oauth'], false)
  if (disabled) {
    return { id: 'oauth_pkce_audience', status: 'fail', detail: 'Explicitly disabled PKCE or OAuth verification detected.' }
  }
  const audValues = collectValues(sig.allObjects, ['expectedAudience', 'audience', 'oauth', 'pkce', 'resource'])
  const hasAudArg = sig.allStrings.some((s) => s.startsWith('--audience=') || s.includes('STEALTHMARK_AUDIENCE'))
  if (audValues.some(isPositiveEvidence) || hasAudArg) {
    return { id: 'oauth_pkce_audience', status: 'pass', detail: 'Explicit OAuth/PKCE or resource audience binding configured.' }
  }
  return { id: 'oauth_pkce_audience', status: 'warn', detail: 'No explicit OAuth 2.1 PKCE or RFC 8707 audience binding declared.' }
}

function isWildcardScopeValue(val: unknown): boolean {
  if (val === false) return true
  if (typeof val === 'string') return WILDCARD_SCOPE_REGEX.test(val.trim())
  if (Array.isArray(val)) return val.some((s) => typeof s === 'string' && WILDCARD_SCOPE_REGEX.test(s.trim()))
  return false
}

function isValidScopeValue(val: unknown): boolean {
  if (Array.isArray(val)) return val.length > 0 && val.every((s) => typeof s === 'string' && s.trim().length > 0)
  return isPositiveEvidence(val)
}

function evalDelegatedOboScope(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const scopeValues = collectValues(sig.allObjects, ['scopes', 'allowedScopes', 'scope', 'delegatedObo', 'obo'])
  if (scopeValues.some(isWildcardScopeValue)) {
    return { id: 'delegated_obo_scope', status: 'fail', detail: 'Over-privileged wildcard or admin scope detected.' }
  }
  if (scopeValues.some(isValidScopeValue)) {
    return { id: 'delegated_obo_scope', status: 'pass', detail: 'Scoped least-privilege OBO permissions declared.' }
  }
  return { id: 'delegated_obo_scope', status: 'warn', detail: 'No explicit OAuth/OBO scope allowlist declared.' }
}

function isValidSchemaPin(val: unknown): boolean {
  if (typeof val === 'string') return SHA256_HEX_REGEX.test(val.trim())
  if (isPlainObject(val)) {
    const vals = Object.values(val)
    return vals.length > 0 && vals.every((v) => typeof v === 'string' && SHA256_HEX_REGEX.test(v.trim()))
  }
  return false
}

function evalToolSchemaSha256Pin(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const skipPin =
    hasBooleanFlag(sig.allObjects, ['skipSchemaPin'], true) ||
    hasBooleanFlag(sig.allObjects, ['verifyToolSchemas'], false)
  if (skipPin) {
    return { id: 'tool_schema_sha256_pin', status: 'fail', detail: 'Tool schema integrity verification is explicitly disabled.' }
  }
  const pinValues = collectValues(sig.allObjects, ['schemaSha256', 'expectedSchemaSha256', 'toolSchemaPin', 'toolSchemaPins', 'integrity'])
  if (pinValues.some((v) => !isValidSchemaPin(v))) {
    return { id: 'tool_schema_sha256_pin', status: 'fail', detail: 'Configured tool schema pin is not a valid 64-hex SHA-256 digest.' }
  }
  if (pinValues.length > 0) {
    return { id: 'tool_schema_sha256_pin', status: 'pass', detail: 'Valid 64-character SHA-256 tool schema pin configured.' }
  }
  return { id: 'tool_schema_sha256_pin', status: 'warn', detail: 'No tool schema SHA-256 integrity pin configured against rug-pulls.' }
}

function evalArgumentSsrfGuard(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const ssrfDisabled = hasBooleanFlag(sig.allObjects, ['blockPrivateNetworkUrls', 'blockPrivateNetworks', 'ssrfGuard'], false)
  if (sig.hasSsrfUrl || ssrfDisabled) {
    return {
      id: 'argument_ssrf_guard',
      status: 'fail',
      detail: 'Cloud metadata / RFC1918 / non-canonical IP target detected or SSRF guard explicitly disabled.',
    }
  }
  const guardValues = collectValues(sig.allObjects, ['blockPrivateNetworkUrls', 'blockPrivateNetworks', 'ssrfGuard'])
  if (sig.serverEntries.length === 0 && !guardValues.some((v) => v === true)) {
    return { id: 'argument_ssrf_guard', status: 'warn', detail: 'No MCP servers declared in configuration.' }
  }
  return { id: 'argument_ssrf_guard', status: 'pass', detail: 'No metadata or private-network SSRF targets present and guard not disabled.' }
}

function isValidAlwaysAllow(val: unknown): boolean {
  return Array.isArray(val) && val.length > 0 && val.every((v) => typeof v === 'string' && v.trim().length > 0 && v !== '*')
}

function evalReadWriteHitlSplit(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const alwaysAllowValues = collectValues(sig.allObjects, ['alwaysAllow'])
  const wildcardAlwaysAllow = alwaysAllowValues.some((v) => v === true || v === '*' || (Array.isArray(v) && v.includes('*')))
  const disabledHitl =
    hasBooleanFlag(sig.allObjects, ['autoApprove'], true) ||
    hasBooleanFlag(sig.allObjects, ['hitl', 'approvalRequired', 'requiresConfirmation', 'requireApproval'], false)
  if (disabledHitl || wildcardAlwaysAllow) {
    return { id: 'read_write_hitl_split', status: 'fail', detail: 'Unrestricted autoApprove, disabled HITL, or wildcard alwaysAllow detected.' }
  }
  const hitlValues = collectValues(sig.allObjects, ['hitl', 'approvalRequired', 'requiresConfirmation', 'readOnly'])
  if (hitlValues.some((v) => v === true) || alwaysAllowValues.some(isValidAlwaysAllow)) {
    return { id: 'read_write_hitl_split', status: 'pass', detail: 'Explicit HITL approval or read-only / bounded tool policy configured.' }
  }
  return { id: 'read_write_hitl_split', status: 'warn', detail: 'No read/write HITL confirmation split declared.' }
}

function evalSessionBudgetLimit(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const keys = ['maxSessionCalls', 'maxCallsPerSession', 'sessionBudget', 'budgetLimit', 'rateLimit', 'maxPayloadBytes', 'maxToolInputElements', 'timeoutMs']
  const budgetValues = collectValues(sig.allObjects, keys)
  const invalidBudget = budgetValues.some(
    (v) => v === false || (typeof v === 'number' && v <= 0) || (typeof v === 'string' && /^(?:unlimited|none|0)$/i.test(v.trim()))
  )
  if (hasBooleanFlag(sig.allObjects, ['disableRateLimit'], true) || invalidBudget) {
    return { id: 'session_budget_limit', status: 'fail', detail: 'Session rate or budget limits are explicitly disabled or non-positive.' }
  }
  if (budgetValues.some(isPositiveEvidence)) {
    return { id: 'session_budget_limit', status: 'pass', detail: 'Bounded session budget, payload, or rate limits configured.' }
  }
  return { id: 'session_budget_limit', status: 'warn', detail: 'No session call budget or payload size limit declared.' }
}

function evalOutputPromptSanitization(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const keys = ['sanitizeOutput', 'outputSanitization', 'stripInvisibleUnicode', 'promptGuard']
  const disabled = hasBooleanFlag(sig.allObjects, keys, false) || hasBooleanFlag(sig.allObjects, ['disableOutputSanitization'], true)
  if (sig.hasInvisibleUnicode || disabled) {
    return {
      id: 'output_prompt_sanitization',
      status: 'fail',
      detail: 'Invisible/bidi Unicode detected in config or output sanitization explicitly disabled.',
    }
  }
  if (collectValues(sig.allObjects, keys).some((v) => v === true || (isPlainObject(v) && Object.keys(v).length > 0))) {
    return { id: 'output_prompt_sanitization', status: 'pass', detail: 'Output sanitization / prompt-injection stripping enabled.' }
  }
  return { id: 'output_prompt_sanitization', status: 'warn', detail: 'Output prompt sanitization policy not explicitly declared.' }
}

function evalZeroPlaintextEnvSecrets(sig: ExtractedMcpSignals): McpConfigControlFinding {
  if (sig.hasPlaintextSecret) {
    return {
      id: 'zero_plaintext_env_secrets',
      status: 'fail',
      detail: 'Plaintext API key, token, or private key material detected in env, args, or headers.',
    }
  }
  if (sig.serverEntries.length === 0) {
    return { id: 'zero_plaintext_env_secrets', status: 'warn', detail: 'No MCP servers declared in configuration.' }
  }
  return {
    id: 'zero_plaintext_env_secrets',
    status: 'pass',
    detail: 'No plaintext secrets detected; credentials use environment variable references.',
  }
}

function isUnsafeEgressEntry(val: unknown): boolean {
  if (val === false || val === '*') return true
  if (typeof val === 'string') return !isSafeTargetDomain(val)
  if (Array.isArray(val)) return val.some((d) => typeof d !== 'string' || d === '*' || !isSafeTargetDomain(d))
  return false
}

function isValidEgressEntry(val: unknown): boolean {
  if (val === true) return true
  if (typeof val === 'string') return isSafeTargetDomain(val)
  return Array.isArray(val) && val.length > 0 && val.every((d) => typeof d === 'string' && isSafeTargetDomain(d))
}

function evalEgressDomainAllowlist(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const allowlistValues = collectValues(sig.allObjects, ['allowedDomains', 'egressAllowlist', 'allowedHosts'])
  if (sig.hasNonLoopbackHttp || sig.hasSsrfUrl || allowlistValues.some(isUnsafeEgressEntry)) {
    return {
      id: 'egress_domain_allowlist',
      status: 'fail',
      detail: 'Cleartext non-loopback http:// URL, unsafe domain, metadata target, or wildcard egress allowlist detected.',
    }
  }
  if (allowlistValues.some(isValidEgressEntry)) {
    return { id: 'egress_domain_allowlist', status: 'pass', detail: 'Explicit HTTPS egress domain allowlist configured.' }
  }
  return {
    id: 'egress_domain_allowlist',
    status: 'warn',
    detail: 'No explicit egress domain allowlist is declared.',
  }
}

function evalEcsImmutableTelemetry(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const keys = ['telemetry', 'auditLog', 'ecsTelemetry', 'immutableAudit']
  const disabled = hasBooleanFlag(sig.allObjects, keys, false) || hasBooleanFlag(sig.allObjects, ['disableTelemetry'], true)
  if (disabled) {
    return { id: 'ecs_immutable_telemetry', status: 'fail', detail: 'Immutable audit logging or telemetry is explicitly disabled.' }
  }
  if (collectValues(sig.allObjects, keys).some(isPositiveEvidence)) {
    return { id: 'ecs_immutable_telemetry', status: 'pass', detail: 'Structured audit telemetry configured.' }
  }
  return { id: 'ecs_immutable_telemetry', status: 'warn', detail: 'No immutable ECS audit telemetry configuration declared.' }
}

function evalWebSurfaceAsphyxiation(sig: ExtractedMcpSignals): McpConfigControlFinding {
  const hasWildcardBind = sig.allStrings.some((s) => BIND_ALL_REGEX.test(s) || s.trim() === '0.0.0.0')
  const wildcardCors = collectValues(sig.allObjects, ['corsOrigin']).some((v) => v === '*' || (Array.isArray(v) && v.includes('*')))
  const unauthOrDisabled =
    hasBooleanFlag(sig.allObjects, ['allowUnauthenticated'], true) ||
    hasBooleanFlag(sig.allObjects, ['authRequired', 'localOnly'], false)
  if (hasWildcardBind || wildcardCors || unauthOrDisabled) {
    return {
      id: 'web_surface_asphyxiation',
      status: 'fail',
      detail: '0.0.0.0 network bind, wildcard CORS, or unauthenticated exposure configured.',
    }
  }
  if (sig.serverEntries.length === 0) {
    return { id: 'web_surface_asphyxiation', status: 'warn', detail: 'No MCP servers declared in configuration.' }
  }
  const hardened = collectValues(sig.allObjects, ['localOnly', 'bindHost', 'disableDiscovery', 'authRequired']).some(isPositiveEvidence)
  if (hardened || sig.serverEntries.every((srv) => typeof srv.url !== 'string')) {
    return { id: 'web_surface_asphyxiation', status: 'pass', detail: 'Local-only stdio or restricted-surface exposure posture.' }
  }
  return { id: 'web_surface_asphyxiation', status: 'warn', detail: 'Remote MCP endpoint lacks explicit bind/CORS/auth surface restrictions.' }
}

/** Deterministically evaluates an mcp.json configuration against the 12 MCP security controls without network calls. */
export function auditMcpConfigJson(rawConfigJson: string): McpConfigAuditResult {
  let parsed: unknown
  try {
    parsed = JSON.parse(rawConfigJson)
  } catch {
    throw new Error('Invalid MCP config JSON: failed to parse JSON')
  }

  if (!isPlainObject(parsed)) {
    throw new Error('Invalid MCP config JSON: expected a top-level JSON object')
  }

  const sig = extractMcpSignals(parsed, rawConfigJson)
  const controls: McpConfigControlFinding[] = [
    evalStdioIsolation(sig),
    evalOauthPkceAudience(sig),
    evalDelegatedOboScope(sig),
    evalToolSchemaSha256Pin(sig),
    evalArgumentSsrfGuard(sig),
    evalReadWriteHitlSplit(sig),
    evalSessionBudgetLimit(sig),
    evalOutputPromptSanitization(sig),
    evalZeroPlaintextEnvSecrets(sig),
    evalEgressDomainAllowlist(sig),
    evalEcsImmutableTelemetry(sig),
    evalWebSurfaceAsphyxiation(sig),
  ]

  const passedCount = controls.filter((c) => c.status === 'pass').length
  const warningCount = controls.filter((c) => c.status === 'warn').length
  const failedCount = controls.filter((c) => c.status === 'fail').length
  const score = Math.max(0, Math.round(((passedCount + warningCount * 0.5) / 12) * 100))

  return {
    score,
    controlsAssessed: 12,
    passedCount,
    warningCount,
    failedCount,
    serverNames: sig.serverNames,
    controls,
  }
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
