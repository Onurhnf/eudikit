/**
 * `verifier.requests.create()` — the request-production pipeline.
 *
 * Two shapes come out of here in this release, one per channel family:
 *
 *  - `'dc-api'` → an `openid4vp-v1-unsigned` request object for
 *    `navigator.credentials.get()`. Unsigned requests carry no `client_id` (OpenID4VP 1.0
 *    Appendix A: it MUST be omitted — the wallet derives the audience from the calling origin)
 *    and no `state` — the caller carries the session id in its own context.
 *  - `'qr' | 'deep-link'` → a by-value `{scheme}://authorize?…` URI with
 *    `response_mode=direct_post`, where `state` carries the session id and comes back in the
 *    wallet's form POST.
 *
 * Every request gets fresh entropy: nonce and session id are independent 32-byte random values,
 * and encrypted flows additionally get a per-request P-256 key pair whose private half is stored
 * only in the session record — no output of this module ever contains it.
 *
 * Signed request objects (JAR), `request_uri` transport and encrypted `direct_post.jwt`
 * responses are not built yet; every path that would need them throws `notImplemented` instead
 * of silently downgrading to an unsigned or unencrypted request.
 */

import { createHash, randomBytes } from 'node:crypto'
import { buildDcqlQuery } from '../dcql/build.js'
import { notImplemented } from '../internal/not-implemented.js'
import type {
  Channel,
  CreatedRequest,
  CreateRequestOptions,
  DcqlQuery,
  Jwk,
  PresetDefinition,
  WalletProfile,
} from '../types.js'
import { EudikitError } from '../types.js'
import {
  type ResolvedVerifierConfig,
  requirePublicBaseUrl,
  validateClientIdPrefix,
  validateExpectedOrigins,
  validateProfile,
  validateTtlSeconds,
} from './config.js'
import { generateEphemeralEncryptionKey } from './ephemeral-key.js'

const NONCE_BYTES = 32
const SESSION_ID_BYTES = 32
const DEFAULT_SCHEME = 'eudi-openid4vp'
const DEEP_LINK_AUTHORITY = 'authorize'
const SESSION_KEY_PREFIX = 'request:'

/** RFC 3986 §3.1 scheme syntax. */
const SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*$/

/**
 * Versioned shape of a pending-request record. Internal — not a public contract. `state` and
 * `responseUri` exist only for the direct_post channels, `ephemeralPrivateJwk` only for
 * encrypted flows, `presetId` only for preset-built requests and `successRedirectTemplate`
 * only for the redirect return mode; a field that means nothing in a given flow is absent,
 * not null.
 */
export interface PendingRequestRecord extends Record<string, unknown> {
  v: 1
  nonce: string
  profile: WalletProfile
  channel: Channel
  dcql: DcqlQuery
  expectedOrigins: string[]
  createdAt: string
  state?: string
  responseUri?: string
  ephemeralPrivateJwk?: Jwk
  presetId?: string
  successRedirectTemplate?: string
}

/** Narrows a stored record to the versioned pending-request shape; `null` on any mismatch. */
export function parsePendingRequestRecord(
  record: Record<string, unknown>
): PendingRequestRecord | null {
  if (record.v !== 1) return null
  if (typeof record.nonce !== 'string') return null
  if (record.profile !== 'av' && record.profile !== 'eudi') return null
  if (typeof record.dcql !== 'object' || record.dcql === null) return null
  return record as PendingRequestRecord
}

export { SESSION_KEY_PREFIX as REQUEST_KEY_PREFIX }

interface RequestContext {
  config: ResolvedVerifierConfig
  dcql: DcqlQuery
  profile: WalletProfile
  nonce: string
  sessionId: string
  ttlSeconds: number
  expectedOrigins: string[]
  createdAt: Date
  expiresAt: Date
  presetId?: string
}

/**
 * Registry key for a preset instance. The preset `id` alone is not enough — two `presets.age()`
 * calls with different thresholds share the id but extract different claims — so the key also
 * fingerprints the emitted query. Deterministic across processes: the same preset options
 * always produce the same key.
 */
export function presetRegistryKey(preset: PresetDefinition<unknown>): string {
  const fingerprint = createHash('sha256')
    .update(JSON.stringify(preset.dcql))
    .digest('base64url')
    .slice(0, 16)
  return `${preset.id}#${fingerprint}`
}

function invalid(detail: string): never {
  throw new EudikitError('CONFIG_INVALID', detail)
}

export async function createRequest(
  config: ResolvedVerifierConfig,
  options: CreateRequestOptions<unknown>
): Promise<CreatedRequest> {
  if (typeof options !== 'object' || options === null) {
    invalid('requests.create(options) needs an options object')
  }

  const channel = validateChannel(options.channel)
  const dcql = resolveDcql(options)
  const profile =
    options.profile === undefined
      ? config.profile
      : validateProfile(options.profile, 'options.profile')

  if (profile === 'av' && channel === 'dc-api') {
    throw new EudikitError(
      'CHANNEL_PROFILE_MISMATCH',
      "channel 'dc-api' cannot reach profile 'av': today's AV wallet accepts only the " +
        'org-iso-mdoc protocol over the Digital Credentials API, so an openid4vp-v1-* request ' +
        'shows no credential in the picker and produces no error. Use channel ' +
        "'deep-link' or 'qr' for the AV wallet; 'dc-api' targets profile 'eudi' wallets."
    )
  }

  const clientIdPrefix =
    options.clientIdPrefix === undefined
      ? config.clientIdPrefix
      : validateClientIdPrefix(options.clientIdPrefix, 'options.clientIdPrefix')
  if (clientIdPrefix !== 'redirect_uri') {
    if (options.signedRequest === false) {
      invalid(
        `clientIdPrefix '${clientIdPrefix}' requires a signed request object ` +
          '(OpenID4VP 1.0 §5.10), so signedRequest cannot be false'
      )
    }
    notImplemented('signed request objects (JAR)')
  }

  const signedRequest =
    optionalBoolean(options.signedRequest, 'options.signedRequest') ??
    (channel === 'dc-api' ? false : profile === 'eudi')
  if (signedRequest) notImplemented('signed request objects (JAR)')

  const context: RequestContext = buildContext(config, options, dcql, profile)

  if (channel === 'dc-api') {
    return createDcApiRequest(context, options)
  }
  return createDirectPostRequest(context, options, channel)
}

function buildContext(
  config: ResolvedVerifierConfig,
  options: CreateRequestOptions<unknown>,
  dcql: DcqlQuery,
  profile: WalletProfile
): RequestContext {
  const ttlSeconds =
    options.ttlSeconds === undefined
      ? config.requestTtlSeconds
      : validateTtlSeconds(options.ttlSeconds, 'options.ttlSeconds', config.requestTtlSeconds)
  const createdAt = config.now()
  return {
    config,
    dcql,
    profile,
    nonce: resolveNonce(options.nonce),
    sessionId: randomBase64Url(SESSION_ID_BYTES),
    ttlSeconds,
    expectedOrigins:
      options.expectedOrigins === undefined
        ? config.expectedOrigins
        : validateExpectedOrigins(options.expectedOrigins, 'options.expectedOrigins'),
    createdAt,
    expiresAt: new Date(createdAt.getTime() + ttlSeconds * 1000),
    ...(options.preset !== undefined
      ? { presetId: presetRegistryKey(options.preset as PresetDefinition<unknown>) }
      : {}),
  }
}

// ---------------------------------------------------------------------------
// channel 'dc-api'
// ---------------------------------------------------------------------------

async function createDcApiRequest(
  context: RequestContext,
  options: CreateRequestOptions<unknown>
): Promise<CreatedRequest> {
  // The profile × channel matrix defaults 'eudi' + 'dc-api' to the encrypted dc_api.jwt mode.
  const encryptResponse =
    optionalBoolean(options.encryptResponse, 'options.encryptResponse') ?? true

  const data: Record<string, unknown> = {
    response_type: 'vp_token',
    response_mode: encryptResponse ? 'dc_api.jwt' : 'dc_api',
    nonce: context.nonce,
    dcql_query: context.dcql,
  }

  let ephemeralPrivateJwk: Jwk | undefined
  if (encryptResponse) {
    const key = await generateEphemeralEncryptionKey()
    ephemeralPrivateJwk = key.privateJwk
    data.client_metadata = {
      jwks: { keys: [key.publicJwk] },
      encrypted_response_enc_values_supported: ['A128GCM'],
    }
  }

  await storeRecord(context, 'dc-api', {
    ...(ephemeralPrivateJwk !== undefined ? { ephemeralPrivateJwk } : {}),
  })

  return {
    channel: 'dc-api',
    sessionId: context.sessionId,
    dcApiRequest: { protocol: 'openid4vp-v1-unsigned', data },
    expiresAt: context.expiresAt,
  }
}

// ---------------------------------------------------------------------------
// channels 'qr' | 'deep-link' (by-value, direct_post)
// ---------------------------------------------------------------------------

async function createDirectPostRequest(
  context: RequestContext,
  options: CreateRequestOptions<unknown>,
  channel: 'qr' | 'deep-link'
): Promise<CreatedRequest> {
  if (context.profile === 'av' && options.encryptResponse === true) {
    invalid(
      "the 'av' profile cannot use encrypted responses: the AV profile (Annex A) mandates " +
        'plain direct_post, and its wallet would reject direct_post.jwt'
    )
  }
  const encryptResponse =
    optionalBoolean(options.encryptResponse, 'options.encryptResponse') ??
    context.profile === 'eudi'
  if (encryptResponse) notImplemented('encrypted direct_post responses (direct_post.jwt)')

  const jarMode = resolveJarMode(options.jarMode)
  if (jarMode === 'by-reference') notImplemented('request_uri (JAR by reference)')

  const scheme = resolveScheme(options.scheme)
  const successRedirectTemplate = resolveSuccessRedirectTemplate(options.successRedirectTemplate)
  const base = requirePublicBaseUrl(context.config, channel)
  const responseUri = `${base}${context.config.routeBasePath}/wallet/response`

  const params = new URLSearchParams()
  params.set('client_id', `redirect_uri:${responseUri}`)
  params.set('response_type', 'vp_token')
  params.set('response_mode', 'direct_post')
  params.set('nonce', context.nonce)
  params.set('state', context.sessionId)
  params.set('response_uri', responseUri)
  params.set('dcql_query', JSON.stringify(context.dcql))
  // The URI needs an authority: the AV wallet registers its deep-link intent filter with host
  // `authorize`, and a URI with an empty authority never matches on Android, while iOS ignores
  // the host.
  const uri = `${scheme}://${DEEP_LINK_AUTHORITY}?${params.toString()}`

  await storeRecord(context, channel, {
    state: context.sessionId,
    responseUri,
    ...(successRedirectTemplate !== undefined ? { successRedirectTemplate } : {}),
  })

  if (channel === 'qr') {
    return {
      channel: 'qr',
      sessionId: context.sessionId,
      qrPayload: uri,
      expiresAt: context.expiresAt,
    }
  }
  return {
    channel: 'deep-link',
    sessionId: context.sessionId,
    deepLink: uri,
    expiresAt: context.expiresAt,
  }
}

// ---------------------------------------------------------------------------
// shared pieces
// ---------------------------------------------------------------------------

async function storeRecord(
  context: RequestContext,
  channel: Channel,
  extra: Partial<PendingRequestRecord>
): Promise<void> {
  const record: PendingRequestRecord = {
    v: 1,
    nonce: context.nonce,
    profile: context.profile,
    channel,
    dcql: context.dcql,
    expectedOrigins: context.expectedOrigins,
    createdAt: context.createdAt.toISOString(),
    ...(context.presetId !== undefined ? { presetId: context.presetId } : {}),
    ...extra,
  }
  await context.config.session.set(
    `${SESSION_KEY_PREFIX}${context.sessionId}`,
    record,
    context.ttlSeconds
  )
}

const RESPONSE_CODE_PLACEHOLDER = '{RESPONSE_CODE}'

function resolveSuccessRedirectTemplate(value: unknown): string | undefined {
  if (value === undefined) return undefined
  if (typeof value !== 'string' || value.length === 0) {
    invalid('options.successRedirectTemplate must be a non-empty URL template string')
  }
  if (!value.includes(RESPONSE_CODE_PLACEHOLDER)) {
    invalid(
      `options.successRedirectTemplate must contain the ${RESPONSE_CODE_PLACEHOLDER} ` +
        'placeholder — without it the redirect would carry no fresh secret and the response ' +
        'endpoint would be unprotected (OpenID4VP 1.0 §14.3.3)'
    )
  }
  try {
    new URL(value.replace(RESPONSE_CODE_PLACEHOLDER, 'probe'))
  } catch {
    invalid(`options.successRedirectTemplate "${value}" is not a valid absolute URL template`)
  }
  return value
}

export { RESPONSE_CODE_PLACEHOLDER }

function resolveDcql(options: CreateRequestOptions<unknown>): DcqlQuery {
  const hasPreset = options.preset !== undefined
  const hasDcql = options.dcql !== undefined
  if (hasPreset === hasDcql) {
    invalid(
      hasPreset
        ? 'requests.create takes either `preset` or `dcql`, not both — a preset already ' +
            'carries its query'
        : 'requests.create needs a credential query: pass `preset` (e.g. presets.age()) or a ' +
            'raw `dcql` query'
    )
  }

  if (hasPreset) {
    const preset = options.preset
    if (
      preset === undefined ||
      typeof preset !== 'object' ||
      typeof preset.extract !== 'function' ||
      typeof preset.dcql !== 'object' ||
      preset.dcql === null
    ) {
      invalid(
        'options.preset does not look like a PresetDefinition — use presets.age(), ' +
          'presets.country() or definePreset()'
      )
    }
    return preset.dcql
  }

  const query = options.dcql
  if (
    query === undefined ||
    typeof query !== 'object' ||
    query === null ||
    !Array.isArray(query.credentials)
  ) {
    invalid('options.dcql must be a DCQL query object with a `credentials` array')
  }
  // Structural validation only; the caller's object is passed through verbatim so extension
  // properties (tolerated by the spec) survive untouched.
  buildDcqlQuery(query.credentials, query.credential_sets)
  return query
}

function validateChannel(value: unknown): Channel {
  if (value === 'dc-api' || value === 'qr' || value === 'deep-link') return value
  invalid(`options.channel must be 'dc-api', 'qr' or 'deep-link', got ${JSON.stringify(value)}`)
}

function resolveJarMode(value: unknown): 'by-value' | 'by-reference' {
  if (value === undefined) return 'by-value'
  if (value === 'by-value' || value === 'by-reference') return value
  invalid(`options.jarMode must be 'by-value' or 'by-reference', got ${JSON.stringify(value)}`)
}

function resolveScheme(value: unknown): string {
  if (value === undefined) return DEFAULT_SCHEME
  if (typeof value !== 'string' || !SCHEME_PATTERN.test(value)) {
    invalid(
      `options.scheme must be a URI scheme like "${DEFAULT_SCHEME}" or "av", ` +
        `got ${JSON.stringify(value)}`
    )
  }
  return value
}

function resolveNonce(value: unknown): string {
  if (value === undefined) return randomBase64Url(NONCE_BYTES)
  if (typeof value !== 'string' || value.length === 0) {
    invalid('options.nonce must be a non-empty string — omit it to let the SDK generate one')
  }
  return value
}

function optionalBoolean(value: unknown, source: string): boolean | undefined {
  if (value === undefined) return undefined
  if (typeof value !== 'boolean') {
    invalid(`${source} must be a boolean, got ${JSON.stringify(value)}`)
  }
  return value
}

function randomBase64Url(bytes: number): string {
  return randomBytes(bytes).toString('base64url')
}
