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

export interface AuditConfigDeps {
  isSafeTargetDomain: (rawDomain: string) => boolean
  isBlockedIpOrHostname: (rawHostname: string) => boolean
  isNonCanonicalIpLiteral: (rawHost: string) => boolean
  extractRawHostSegment: (rawUrlOrDomain: string) => string
  invisibleBidiTestRegex: RegExp
}

const PLAINTEXT_SECRET_REGEX =
  /(?:(?<![A-Za-z0-9_-])(?:sk_live_[A-Za-z0-9_-]+|sk-proj-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|re_[A-Za-z0-9_-]{16,}|rk_live_[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]+|gho_[A-Za-z0-9]+|AIza[0-9A-Za-z_-]+|AKIA[0-9A-Z]{16}|xoxb-[0-9A-Za-z-]+|xoxp-[0-9A-Za-z-]+|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i
const SHELL_COMMAND_REGEX = /(?:^|[\\/])(?:sh|bash|zsh|dash|ksh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/i
const SHELL_EXEC_ARG_REGEX = /\b(?:sh|bash|zsh)\s+-c\b|\bcmd(?:\.exe)?\s+\/c\b|\bpowershell(?:\.exe)?\s+-c\b/i
const SHELL_METACHAR_ARG_REGEX = /`|\$\(|&&|\|\||;\s|\|\s/
const INSPECT_FLAG_REGEX = /--inspect(?:-brk)?(?:=|\b)/i
const BIND_ALL_REGEX = /(?:^|[\s=:("'\[/])(?:0\.0\.0\.0(?::\d+)?|\[::\](?::\d+)?)(?=$|[\s"'\]/,;)])/i
const FORCE_AUTH_LOCALHOST_FLAG_REGEX = /--force-auth-localhost\b|--trust-localhost\b/i
const HTTP_URL_REGEX = /(?:https?:\/\/|(?<=^|[\s"'`=(])\/\/)[^\s"'`<>]+/gi
const NON_HTTP_SSRF_PROBE_REGEX = /(?:file:\/\/|169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|metadata\.goog|fd00:ec2::254)/i
const WILDCARD_SCOPE_REGEX = /^(?:\*|admin:\*|root|full_access|superuser)$/i

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

interface ExtractedMcpSignals {
  serverNames: string[]
  serverPairs: Array<{ name: string; cfg: Record<string, unknown> }>
  serverEntries: Record<string, unknown>[]
  topLevelObjects: Record<string, unknown>[]
  allObjects: Record<string, unknown>[]
  allStrings: string[]
  envAndArgStrings: string[]
  urlStrings: string[]
  hasShellInvocation: boolean
  hasShellMetacharArg: boolean
  hasInspectFlag: boolean
  hasPrivilegedStdio: boolean
  hasPlaintextSecret: boolean
  hasSsrfUrl: boolean
  hasNonLoopbackHttp: boolean
  hasInvisibleUnicode: boolean
  hasStandaloneIpv6AnyArg: boolean
}

function uncoveredServers(
  sig: ExtractedMcpSignals,
  keys: string[],
  predicate: (val: unknown) => boolean,
  serverExtraCheck?: (srv: Record<string, unknown>) => boolean
): { covered: boolean; missing: string[] } {
  if (collectValues(sig.topLevelObjects, keys).some(predicate)) {
    return { covered: true, missing: [] }
  }
  if (sig.serverPairs.length === 0) {
    return { covered: false, missing: [] }
  }
  const missing: string[] = []
  for (const { name, cfg } of sig.serverPairs) {
    const ok =
      collectValues([cfg], keys).some(predicate) || (serverExtraCheck ? serverExtraCheck(cfg) : false)
    if (!ok) missing.push(name)
  }
  return { covered: missing.length === 0, missing }
}

function coverageVerdict(
  id: string,
  sig: ExtractedMcpSignals,
  coverage: { covered: boolean; missing: string[] },
  passWithServers: string,
  passTopLevelOnly: string,
  partialPrefix: string,
  missingAllDetail: string
): McpConfigControlFinding {
  if (coverage.covered) {
    return {
      id,
      status: 'pass',
      detail: sig.serverPairs.length > 0 ? passWithServers : passTopLevelOnly,
    }
  }
  if (coverage.missing.length > 0 && coverage.missing.length < sig.serverPairs.length) {
    return { id, status: 'warn', detail: `${partialPrefix}: ${coverage.missing.join(', ')}.` }
  }
  return { id, status: 'warn', detail: missingAllDetail }
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

function isValidSchemaPin(val: unknown): boolean {
  if (typeof val === 'string') return SHA256_HEX_REGEX.test(val.trim())
  if (isPlainObject(val)) {
    const vals = Object.values(val)
    return vals.length > 0 && vals.every((v) => typeof v === 'string' && SHA256_HEX_REGEX.test(v.trim()))
  }
  return false
}

function isValidAlwaysAllow(val: unknown): boolean {
  return Array.isArray(val) && val.length > 0 && val.every((v) => typeof v === 'string' && v.trim().length > 0 && v !== '*')
}

/** Deterministically evaluates an mcp.json configuration against the 12 MCP security controls without network calls. */
export function runMcpConfigAudit(rawConfigJson: string, deps: AuditConfigDeps): McpConfigAuditResult {
  let parsed: unknown
  try {
    parsed = JSON.parse(rawConfigJson)
  } catch {
    throw new Error('Invalid MCP config JSON: failed to parse JSON')
  }

  if (!isPlainObject(parsed)) {
    throw new Error('Invalid MCP config JSON: expected a top-level JSON object')
  }

  const isLoopbackHttpUrl = (urlStr: string): boolean => {
    try {
      const rawHost = deps.extractRawHostSegment(urlStr.normalize('NFKC').trim()).toLowerCase().replace(/\.+$/, '')
      if (rawHost !== 'localhost' && rawHost !== '127.0.0.1' && rawHost !== '[::1]') return false
      return new URL(urlStr).protocol === 'http:'
    } catch {
      return false
    }
  }

  const isSsrfUrlCandidate = (urlStr: string): boolean => {
    const normalized = urlStr.normalize('NFKC').trim()
    if (NON_HTTP_SSRF_PROBE_REGEX.test(normalized)) return true
    const rawHost = deps.extractRawHostSegment(normalized.replace(/^\/\//, ''))
    if (deps.isNonCanonicalIpLiteral(rawHost)) return true
    try {
      const parsedUrl = new URL(normalized.startsWith('//') ? `http:${normalized}` : normalized)
      if (parsedUrl.username !== '' || parsedUrl.password !== '') return true
      const cleanRaw = rawHost.toLowerCase().replace(/\.+$/, '')
      if (cleanRaw === 'localhost' || cleanRaw === '127.0.0.1' || cleanRaw === '[::1]') return false
      return deps.isBlockedIpOrHostname(parsedUrl.hostname)
    } catch {
      return rawHost.length > 0 && deps.isBlockedIpOrHostname(rawHost)
    }
  }

  const serversMap = extractServerMap(parsed)
  const serverPairs = Object.entries(serversMap).map(([name, cfg]) => ({ name, cfg }))
  const serverNames = serverPairs.map((p) => p.name)
  const serverEntries = serverPairs.map((p) => p.cfg)
  const topSecurity = isPlainObject(parsed.security) ? [parsed.security] : []
  const topPolicy = isPlainObject(parsed.policy) ? [parsed.policy] : []
  const topLevelObjects: Record<string, unknown>[] = [...topSecurity, ...topPolicy, parsed]
  const allObjects: Record<string, unknown>[] = [...serverEntries, ...topLevelObjects]

  const allStrings: string[] = []
  collectStrings(parsed, allStrings)

  const envAndArgStrings: string[] = []
  const urlStrings: string[] = []
  let hasShellInvocation = false
  let hasShellMetacharArg = false
  let hasInspectFlag = false
  let hasPrivilegedStdio = false
  let hasStandaloneIpv6AnyArg = false

  for (const srv of serverEntries) {
    const cmd = typeof srv.command === 'string' ? srv.command.trim() : ''
    const args = Array.isArray(srv.args) ? srv.args.filter((a): a is string => typeof a === 'string') : []
    const joined = [cmd, ...args].join(' ').trim()

    if (SHELL_COMMAND_REGEX.test(cmd) || SHELL_EXEC_ARG_REGEX.test(joined)) hasShellInvocation = true
    if (args.some((a) => SHELL_METACHAR_ARG_REGEX.test(a))) hasShellMetacharArg = true
    if (args.some((a) => a.trim() === '::' || /^--(?:host|bind|listen)=::$/i.test(a.trim()))) {
      hasStandaloneIpv6AnyArg = true
    }
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

  const sig: ExtractedMcpSignals = {
    serverNames,
    serverPairs,
    serverEntries,
    topLevelObjects,
    allObjects,
    allStrings,
    envAndArgStrings,
    urlStrings,
    hasShellInvocation,
    hasShellMetacharArg,
    hasInspectFlag,
    hasPrivilegedStdio,
    hasPlaintextSecret:
      envAndArgStrings.some((s) => PLAINTEXT_SECRET_REGEX.test(s)) ||
      allStrings.some((s) => PLAINTEXT_SECRET_REGEX.test(s)) ||
      serverEntries.some((srv) => isPlaintextBearerHeader(srv.headers)),
    hasSsrfUrl: urlStrings.some(isSsrfUrlCandidate),
    hasNonLoopbackHttp: urlStrings.some((u) => /^http:\/\//i.test(u) && !isLoopbackHttpUrl(u)),
    hasInvisibleUnicode:
      deps.invisibleBidiTestRegex.test(rawConfigJson) || allStrings.some((s) => deps.invisibleBidiTestRegex.test(s)),
    hasStandaloneIpv6AnyArg,
  }

  const isUnsafeEgressEntry = (val: unknown): boolean => {
    if (val === false || val === '*') return true
    if (typeof val === 'string') return !deps.isSafeTargetDomain(val)
    if (Array.isArray(val)) return val.some((d) => typeof d !== 'string' || d === '*' || !deps.isSafeTargetDomain(d))
    return false
  }
  const isValidEgressEntry = (val: unknown): boolean => {
    if (val === true) return true
    if (typeof val === 'string') return deps.isSafeTargetDomain(val)
    return Array.isArray(val) && val.length > 0 && val.every((d) => typeof d === 'string' && deps.isSafeTargetDomain(d))
  }

  const controls: McpConfigControlFinding[] = [
    // 1. stdio_isolation
    sig.hasShellInvocation || sig.hasShellMetacharArg || sig.hasInspectFlag || sig.hasPrivilegedStdio
      ? {
          id: 'stdio_isolation',
          status: 'fail',
          detail: 'Detected shell wrapper (sh/bash -c), shell metacharacters in args, debugger (--inspect), or unisolated privileged stdio flag.',
        }
      : sig.serverEntries.length === 0
      ? { id: 'stdio_isolation', status: 'warn', detail: 'No MCP servers declared in configuration.' }
      : {
          id: 'stdio_isolation',
          status: 'pass',
          detail: 'Direct binary/runtime invocation without shell wrappers, command metacharacters, or debugger flags.',
        },

    // 2. oauth_pkce_audience
    hasBooleanFlag(sig.allObjects, ['insecureSkipVerify'], true) || hasBooleanFlag(sig.allObjects, ['pkce', 'oauth'], false)
      ? { id: 'oauth_pkce_audience', status: 'fail', detail: 'Explicitly disabled PKCE or OAuth verification detected.' }
      : coverageVerdict(
          'oauth_pkce_audience',
          sig,
          uncoveredServers(sig, ['expectedAudience', 'audience', 'oauth', 'pkce', 'resource'], isPositiveEvidence, (srv) => {
            const strs: string[] = []
            collectStrings(srv, strs)
            return strs.some((s) => s.startsWith('--audience=') || s.includes('STEALTHMARK_AUDIENCE'))
          }),
          'Explicit OAuth/PKCE or resource audience binding configured across all declared servers.',
          'Top-level OAuth/PKCE or resource audience binding configured.',
          'OAuth/audience binding missing on server(s)',
          'No explicit OAuth 2.1 PKCE or RFC 8707 audience binding declared.'
        ),

    // 3. delegated_obo_scope
    collectValues(sig.allObjects, ['scopes', 'allowedScopes', 'scope', 'delegatedObo', 'obo']).some(isWildcardScopeValue)
      ? { id: 'delegated_obo_scope', status: 'fail', detail: 'Over-privileged wildcard or admin scope detected.' }
      : coverageVerdict(
          'delegated_obo_scope',
          sig,
          uncoveredServers(sig, ['scopes', 'allowedScopes', 'scope', 'delegatedObo', 'obo'], isValidScopeValue),
          'Scoped least-privilege OBO permissions declared across all declared servers.',
          'Top-level scoped least-privilege OBO permissions declared.',
          'OAuth/OBO scope allowlist missing on server(s)',
          'No explicit OAuth/OBO scope allowlist declared.'
        ),

    // 4. tool_schema_sha256_pin
    (() => {
      const skipPin =
        hasBooleanFlag(sig.allObjects, ['skipSchemaPin'], true) ||
        hasBooleanFlag(sig.allObjects, ['verifyToolSchemas'], false)
      if (skipPin) {
        return { id: 'tool_schema_sha256_pin', status: 'fail', detail: 'Tool schema integrity verification is explicitly disabled.' }
      }
      const keys = ['schemaSha256', 'expectedSchemaSha256', 'toolSchemaPin', 'toolSchemaPins', 'integrity']
      if (collectValues(sig.allObjects, keys).some((v) => !isValidSchemaPin(v))) {
        return { id: 'tool_schema_sha256_pin', status: 'fail', detail: 'Configured tool schema pin is not a valid 64-hex SHA-256 digest.' }
      }
      return coverageVerdict(
        'tool_schema_sha256_pin',
        sig,
        uncoveredServers(sig, keys, isValidSchemaPin),
        'Valid 64-character SHA-256 tool schema pin configured across all declared servers.',
        'Top-level 64-character SHA-256 tool schema pin configured.',
        'Tool schema SHA-256 pin missing on server(s)',
        'No tool schema SHA-256 integrity pin configured against rug-pulls.'
      )
    })(),

    // 5. argument_ssrf_guard
    sig.hasSsrfUrl || hasBooleanFlag(sig.allObjects, ['blockPrivateNetworkUrls', 'blockPrivateNetworks', 'ssrfGuard'], false)
      ? {
          id: 'argument_ssrf_guard',
          status: 'fail',
          detail: 'Cloud metadata / RFC1918 / non-canonical IP target detected or SSRF guard explicitly disabled.',
        }
      : sig.serverEntries.length === 0 && !collectValues(sig.allObjects, ['blockPrivateNetworkUrls', 'blockPrivateNetworks', 'ssrfGuard']).some((v) => v === true)
      ? { id: 'argument_ssrf_guard', status: 'warn', detail: 'No MCP servers declared in configuration.' }
      : { id: 'argument_ssrf_guard', status: 'pass', detail: 'No metadata or private-network SSRF targets present and guard not disabled.' },

    // 6. read_write_hitl_split
    (() => {
      const alwaysAllowValues = collectValues(sig.allObjects, ['alwaysAllow'])
      const wildcardAlwaysAllow = alwaysAllowValues.some((v) => v === true || v === '*' || (Array.isArray(v) && v.includes('*')))
      const disabledHitl =
        hasBooleanFlag(sig.allObjects, ['autoApprove'], true) ||
        hasBooleanFlag(sig.allObjects, ['hitl', 'approvalRequired', 'requiresConfirmation', 'requireApproval'], false)
      if (disabledHitl || wildcardAlwaysAllow) {
        return { id: 'read_write_hitl_split', status: 'fail', detail: 'Unrestricted autoApprove, disabled HITL, or wildcard alwaysAllow detected.' }
      }
      const topAlwaysAllow = collectValues(sig.topLevelObjects, ['alwaysAllow']).some(isValidAlwaysAllow)
      const cov = topAlwaysAllow
        ? { covered: true, missing: [] }
        : uncoveredServers(
            sig,
            ['hitl', 'approvalRequired', 'requiresConfirmation', 'readOnly'],
            (v) => v === true,
            (srv) => collectValues([srv], ['alwaysAllow']).some(isValidAlwaysAllow)
          )
      return coverageVerdict(
        'read_write_hitl_split',
        sig,
        cov,
        'Explicit HITL approval or read-only / bounded tool policy configured across all declared servers.',
        'Top-level HITL approval or bounded tool policy configured.',
        'HITL approval policy missing on server(s)',
        'No read/write HITL confirmation split declared.'
      )
    })(),

    // 7. session_budget_limit
    (() => {
      const keys = ['maxSessionCalls', 'maxCallsPerSession', 'sessionBudget', 'budgetLimit', 'rateLimit', 'maxPayloadBytes', 'maxToolInputElements', 'timeoutMs']
      const invalidBudget = collectValues(sig.allObjects, keys).some(
        (v) => v === false || (typeof v === 'number' && v <= 0) || (typeof v === 'string' && /^(?:unlimited|none|0)$/i.test(v.trim()))
      )
      if (hasBooleanFlag(sig.allObjects, ['disableRateLimit'], true) || invalidBudget) {
        return { id: 'session_budget_limit', status: 'fail', detail: 'Session rate or budget limits are explicitly disabled or non-positive.' }
      }
      return coverageVerdict(
        'session_budget_limit',
        sig,
        uncoveredServers(sig, keys, isPositiveEvidence),
        'Bounded session budget, payload, or rate limits configured across all declared servers.',
        'Top-level session budget, payload, or rate limits configured.',
        'Session budget/rate limit missing on server(s)',
        'No session call budget or payload size limit declared.'
      )
    })(),

    // 8. output_prompt_sanitization
    (() => {
      const keys = ['sanitizeOutput', 'outputSanitization', 'stripInvisibleUnicode', 'promptGuard']
      if (sig.hasInvisibleUnicode || hasBooleanFlag(sig.allObjects, keys, false) || hasBooleanFlag(sig.allObjects, ['disableOutputSanitization'], true)) {
        return {
          id: 'output_prompt_sanitization',
          status: 'fail',
          detail: 'Invisible/bidi Unicode detected in config or output sanitization explicitly disabled.',
        }
      }
      return coverageVerdict(
        'output_prompt_sanitization',
        sig,
        uncoveredServers(sig, keys, (v) => v === true || (isPlainObject(v) && Object.keys(v).length > 0)),
        'Output sanitization / prompt-injection stripping enabled across all declared servers.',
        'Top-level output sanitization / prompt-injection stripping enabled.',
        'Output sanitization policy missing on server(s)',
        'Output prompt sanitization policy not explicitly declared.'
      )
    })(),

    // 9. zero_plaintext_env_secrets
    sig.hasPlaintextSecret
      ? {
          id: 'zero_plaintext_env_secrets',
          status: 'fail',
          detail: 'Plaintext API key, token, or private key material detected in env, args, or headers.',
        }
      : sig.serverEntries.length === 0
      ? { id: 'zero_plaintext_env_secrets', status: 'warn', detail: 'No MCP servers declared in configuration.' }
      : {
          id: 'zero_plaintext_env_secrets',
          status: 'pass',
          detail: 'No plaintext secrets detected; credentials use environment variable references.',
        },

    // 10. egress_domain_allowlist
    (() => {
      const keys = ['allowedDomains', 'egressAllowlist', 'allowedHosts']
      if (sig.hasNonLoopbackHttp || sig.hasSsrfUrl || collectValues(sig.allObjects, keys).some(isUnsafeEgressEntry)) {
        return {
          id: 'egress_domain_allowlist',
          status: 'fail',
          detail: 'Cleartext non-loopback http:// URL, unsafe domain, metadata target, or wildcard egress allowlist detected.',
        }
      }
      return coverageVerdict(
        'egress_domain_allowlist',
        sig,
        uncoveredServers(sig, keys, isValidEgressEntry),
        'Explicit HTTPS egress domain allowlist configured across all declared servers.',
        'Top-level HTTPS egress domain allowlist configured.',
        'Egress domain allowlist missing on server(s)',
        'No explicit egress domain allowlist is declared.'
      )
    })(),

    // 11. ecs_immutable_telemetry
    (() => {
      const keys = ['telemetry', 'auditLog', 'ecsTelemetry', 'immutableAudit']
      if (hasBooleanFlag(sig.allObjects, keys, false) || hasBooleanFlag(sig.allObjects, ['disableTelemetry'], true)) {
        return { id: 'ecs_immutable_telemetry', status: 'fail', detail: 'Immutable audit logging or telemetry is explicitly disabled.' }
      }
      return coverageVerdict(
        'ecs_immutable_telemetry',
        sig,
        uncoveredServers(sig, keys, isPositiveEvidence),
        'Structured audit telemetry configured across all declared servers.',
        'Top-level structured audit telemetry configured.',
        'Audit telemetry missing on server(s)',
        'No immutable ECS audit telemetry configuration declared.'
      )
    })(),

    // 12. web_surface_asphyxiation
    (() => {
      const bindValues = collectValues(sig.allObjects, ['bindHost', 'host', 'listen', 'bind'])
      const hasWildcardBind =
        sig.hasStandaloneIpv6AnyArg ||
        sig.allStrings.some((s) => BIND_ALL_REGEX.test(s) || s.trim() === '0.0.0.0') ||
        bindValues.some((v) => typeof v === 'string' && (v.trim() === '::' || BIND_ALL_REGEX.test(v)))
      const wildcardCors = collectValues(sig.allObjects, ['corsOrigin']).some((v) => v === '*' || (Array.isArray(v) && v.includes('*')))
      const trustLoopbackBypass =
        hasBooleanFlag(sig.allObjects, ['forceAuthLocalhost', 'trustLocalhost', 'trustProxyLoopback'], true) ||
        sig.allStrings.some((s) => FORCE_AUTH_LOCALHOST_FLAG_REGEX.test(s))
      const unauthOrDisabled =
        hasBooleanFlag(sig.allObjects, ['allowUnauthenticated'], true) ||
        hasBooleanFlag(sig.allObjects, ['authRequired', 'localOnly'], false)
      if (hasWildcardBind || wildcardCors || trustLoopbackBypass || unauthOrDisabled) {
        return {
          id: 'web_surface_asphyxiation',
          status: 'fail',
          detail: 'Wildcard network bind (0.0.0.0 / [::]), wildcard CORS, loopback auth bypass (force_auth_localhost), or unauthenticated exposure configured.',
        }
      }
      if (sig.serverEntries.length === 0) {
        return { id: 'web_surface_asphyxiation', status: 'warn', detail: 'No MCP servers declared in configuration.' }
      }
      return coverageVerdict(
        'web_surface_asphyxiation',
        sig,
        uncoveredServers(
          sig,
          ['localOnly', 'bindHost', 'disableDiscovery', 'authRequired'],
          isPositiveEvidence,
          (srv) => typeof srv.url !== 'string'
        ),
        'Local-only stdio or restricted-surface exposure posture across all declared servers.',
        'Top-level restricted-surface exposure posture configured.',
        'Remote MCP endpoint(s) lack explicit bind/CORS/auth restrictions',
        'Remote MCP endpoint lacks explicit bind/CORS/auth surface restrictions.'
      )
    })(),
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
