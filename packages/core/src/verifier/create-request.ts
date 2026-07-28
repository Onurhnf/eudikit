/**
 * `verifier.requests.create()` — the request-production pipeline.
 *
 * Shapes that come out of here, per channel family:
 *
 *  - `'dc-api'` → an `openid4vp-v1-unsigned` request object for
 *    `navigator.credentials.get()` — or `openid4vp-v1-signed` (`data.request` = JWS compact,
 *    with the mandatory `expected_origins` claim) when `signedRequest` is on. Unsigned
 *    requests carry no `client_id` (OpenID4VP 1.0 Appendix A: it MUST be omitted — the wallet
 *    derives the audience from the calling origin) and no `state` — the caller carries the
 *    session id in its own context.
 *  - `'qr' | 'deep-link'` unsigned → a by-value `{scheme}://authorize?…` URI with
 *    `response_mode=direct_post[.jwt]`, where `state` carries the session id and comes back
 *    in the wallet's POST.
 *  - `'qr' | 'deep-link'` signed → by default a short by-reference URI,
 *    `{scheme}://authorize?client_id=…&request_uri=…`, whose Request Object is served once by
 *    `handleRequestUri`; `jarMode: 'by-value'` inlines the JWS into a `request` parameter
 *    instead.
 *
 * Signing and transport are coupled by the spec, not by choice: the `redirect_uri` prefix
 * cannot sign (OpenID4VP 1.0 §5.10 — the wallet has no trusted key for it), so by-reference
 * transport — which serves a signed Request Object — is available to signed flows only. The
 * `'av'` profile therefore stays unsigned by-value end to end, and `'eudi'` QR/deep-link
 * defaults to signed by-reference.
 *
 * Every request gets fresh entropy: nonce and session id are independent 32-byte random values,
 * and encrypted flows additionally get a per-request P-256 key pair whose private half is stored
 * only in the session record — no output of this module ever contains it. Encrypted direct_post
 * flows also write a `jwekid:` index record, because a `direct_post.jwt` form carries no
 * `state` field in the clear: the response endpoint finds the session by the JWE header's
 * `kid`, which names the ephemeral key — and therefore the session — it was encrypted to.
 */

import { createHash, randomBytes } from 'node:crypto'
import { buildDcqlQuery } from '../dcql/build.js'
import type {
  Channel,
  ClientIdPrefix,
  CreatedRequest,
  CreateRequestOptions,
  DcqlQuery,
  Jwk,
  PresetDefinition,
  WalletProfile,
} from '../types.js'
import { EudikitError } from '../types.js'
import { SUPPORTED_RESPONSE_ENCRYPTION } from '../verify/envelope.js'
import {
  type ResolvedVerifierConfig,
  requirePublicBaseUrl,
  validateClientIdPrefix,
  validateExpectedOrigins,
  validateProfile,
  validateTtlSeconds,
} from './config.js'
import { generateEphemeralEncryptionKey } from './ephemeral-key.js'
import {
  resolveSignedRequestMaterial,
  type SignedRequestMaterial,
  signRequestObject,
} from './jar.js'

const NONCE_BYTES = 32
const SESSION_ID_BYTES = 32
const DEFAULT_SCHEME = 'eudi-openid4vp'
const DEEP_LINK_AUTHORITY = 'authorize'
const SESSION_KEY_PREFIX = 'request:'
const JWE_KID_KEY_PREFIX = 'jwekid:'

/** RFC 3986 §3.1 scheme syntax. */
const SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*$/

/**
 * Versioned shape of a pending-request record. Internal — not a public contract. `state` and
 * `responseUri` exist only for the direct_post channels, `ephemeralPrivateJwk` only for
 * encrypted flows, `presetId` only for preset-built requests, `successRedirectTemplate` only
 * for the redirect return mode, `clientId` only where a transcript rebuild needs it
 * (direct_post), and `jar`/`jarServed` only for by-reference transport; a field that means
 * nothing in a given flow is absent, not null.
 */
export interface PendingRequestRecord extends Record<string, unknown> {
  v: 1
  nonce: string
  profile: WalletProfile
  channel: Channel
  dcql: DcqlQuery
  expectedOrigins: string[]
  createdAt: string
  expiresAt: string
  state?: string
  responseUri?: string
  clientId?: string
  ephemeralPrivateJwk?: Jwk
  jar?: string
  jarServed?: boolean
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

export { JWE_KID_KEY_PREFIX, SESSION_KEY_PREFIX as REQUEST_KEY_PREFIX }

/** Versioned `jwekid:` index record — resolves a JWE `kid` to its session id. */
export interface JweKidIndexRecord extends Record<string, unknown> {
  v: 1
  sessionId: string
}

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

  const { signedRequest, clientIdPrefix } = resolveSigningAndPrefix(
    config,
    options,
    profile,
    channel
  )
  const material = signedRequest ? resolveSignedRequestMaterial(config, clientIdPrefix) : null

  const context: RequestContext = buildContext(config, options, dcql, profile)

  if (channel === 'dc-api') {
    return createDcApiRequest(context, options, material)
  }
  return createDirectPostRequest(context, options, channel, material)
}

/**
 * Signing and the client id prefix are one decision, not two: the `x509_*` prefixes MUST sign
 * and `redirect_uri` MUST NOT (OpenID4VP 1.0 §5.10). An explicit prefix (per request or in the
 * config) always wins and forces the matching signing behavior. When neither side is forced,
 * the request is signed for `'eudi'` QR/deep-link and unsigned everywhere else, and the
 * default prefix follows that decision: `x509_hash` — the prefix HAIP mandates for EUDI
 * wallets — for signed requests, `redirect_uri` for unsigned ones.
 */
function resolveSigningAndPrefix(
  config: ResolvedVerifierConfig,
  options: CreateRequestOptions<unknown>,
  profile: WalletProfile,
  channel: Channel
): { signedRequest: boolean; clientIdPrefix: ClientIdPrefix } {
  const explicit = optionalBoolean(options.signedRequest, 'options.signedRequest')
  const prefix =
    options.clientIdPrefix === undefined
      ? config.clientIdPrefix
      : validateClientIdPrefix(options.clientIdPrefix, 'options.clientIdPrefix')

  if (prefix !== null && prefix !== 'redirect_uri') {
    if (explicit === false) {
      invalid(
        `clientIdPrefix '${prefix}' requires a signed request object ` +
          '(OpenID4VP 1.0 §5.10), so signedRequest cannot be false'
      )
    }
    return { signedRequest: true, clientIdPrefix: prefix }
  }

  const signed = explicit ?? (channel === 'dc-api' ? false : profile === 'eudi')
  if (!signed) {
    return { signedRequest: false, clientIdPrefix: prefix ?? 'redirect_uri' }
  }

  const effective = prefix ?? (profile === 'eudi' ? 'x509_hash' : 'redirect_uri')
  if (effective === 'redirect_uri') {
    invalid(
      "a signed request object cannot use the 'redirect_uri' client id prefix — the wallet " +
        'has no way to obtain a trusted key for it (OpenID4VP 1.0 §5.10). Configure ' +
        "clientIdPrefix 'x509_san_dns' or 'x509_hash' together with keys.requestSigning and " +
        'keys.requestSigningCertificateChain, or pass signedRequest: false for an unsigned ' +
        'by-value request'
    )
  }
  return { signedRequest: true, clientIdPrefix: effective }
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
  options: CreateRequestOptions<unknown>,
  material: SignedRequestMaterial | null
): Promise<CreatedRequest> {
  // The profile × channel matrix defaults 'eudi' + 'dc-api' to the encrypted dc_api.jwt mode.
  const encryptResponse =
    optionalBoolean(options.encryptResponse, 'options.encryptResponse') ?? true

  const parameters: Record<string, unknown> = {
    response_type: 'vp_token',
    response_mode: encryptResponse ? 'dc_api.jwt' : 'dc_api',
    nonce: context.nonce,
    dcql_query: context.dcql,
  }

  let ephemeralPrivateJwk: Jwk | undefined
  if (encryptResponse) {
    const key = await generateEphemeralEncryptionKey()
    ephemeralPrivateJwk = key.privateJwk
    parameters.client_metadata = {
      jwks: { keys: [key.publicJwk] },
      encrypted_response_enc_values_supported: SUPPORTED_RESPONSE_ENCRYPTION,
    }
  }

  let dcApiRequest: Extract<CreatedRequest, { channel: 'dc-api' }>['dcApiRequest']
  if (material === null) {
    // Unsigned requests MUST omit client_id — the wallet takes its audience from the origin.
    dcApiRequest = { protocol: 'openid4vp-v1-unsigned', data: parameters }
  } else {
    if (context.expectedOrigins.length === 0) {
      invalid(
        'signed DC API requests must pin the origins they may be delivered to via the ' +
          'expected_origins claim (OpenID4VP 1.0 Appendix A.3.2) — set expectedOrigins in the ' +
          'verifier config or per request'
      )
    }
    const jws = await signRequestObject({
      material,
      claims: {
        ...parameters,
        client_id: material.clientId,
        expected_origins: context.expectedOrigins,
      },
      issuedAt: context.createdAt,
      expiresAt: context.expiresAt,
    })
    dcApiRequest = { protocol: 'openid4vp-v1-signed', data: { request: jws } }
  }

  await storeRecord(context, 'dc-api', {
    ...(ephemeralPrivateJwk !== undefined ? { ephemeralPrivateJwk } : {}),
  })

  return {
    channel: 'dc-api',
    sessionId: context.sessionId,
    dcApiRequest,
    expiresAt: context.expiresAt,
  }
}

// ---------------------------------------------------------------------------
// channels 'qr' | 'deep-link' (by-value, direct_post)
// ---------------------------------------------------------------------------

async function createDirectPostRequest(
  context: RequestContext,
  options: CreateRequestOptions<unknown>,
  channel: 'qr' | 'deep-link',
  material: SignedRequestMaterial | null
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

  const jarMode = resolveJarMode(options.jarMode, material)
  const scheme = resolveScheme(options.scheme)
  const successRedirectTemplate = resolveSuccessRedirectTemplate(options.successRedirectTemplate)
  const base = requirePublicBaseUrl(context.config, channel)
  const responseUri = `${base}${context.config.routeBasePath}/wallet/response`
  const clientId = material === null ? `redirect_uri:${responseUri}` : material.clientId
  const responseMode = encryptResponse ? 'direct_post.jwt' : 'direct_post'

  let ephemeralPrivateJwk: Jwk | undefined
  let clientMetadata: Record<string, unknown> | undefined
  if (encryptResponse) {
    const key = await generateEphemeralEncryptionKey()
    ephemeralPrivateJwk = key.privateJwk
    clientMetadata = {
      jwks: { keys: [key.publicJwk] },
      encrypted_response_enc_values_supported: SUPPORTED_RESPONSE_ENCRYPTION,
    }
  }

  // The URI needs an authority: the AV wallet registers its deep-link intent filter with host
  // `authorize`, and a URI with an empty authority never matches on Android, while iOS ignores
  // the host.
  let uri: string
  let requestUri: string | undefined
  let jar: string | undefined
  if (material !== null) {
    const signed = await signRequestObject({
      material,
      claims: {
        client_id: clientId,
        response_type: 'vp_token',
        response_mode: responseMode,
        response_uri: responseUri,
        nonce: context.nonce,
        state: context.sessionId,
        dcql_query: context.dcql,
        ...(clientMetadata !== undefined ? { client_metadata: clientMetadata } : {}),
      },
      issuedAt: context.createdAt,
      expiresAt: context.expiresAt,
    })

    const params = new URLSearchParams()
    params.set('client_id', clientId)
    if (jarMode === 'by-reference') {
      jar = signed
      requestUri = `${base}${context.config.routeBasePath}/wallet/request/${context.sessionId}.jwt`
      params.set('request_uri', requestUri)
    } else {
      params.set('request', signed)
    }
    uri = `${scheme}://${DEEP_LINK_AUTHORITY}?${params.toString()}`
  } else {
    const params = new URLSearchParams()
    params.set('client_id', clientId)
    params.set('response_type', 'vp_token')
    params.set('response_mode', responseMode)
    params.set('nonce', context.nonce)
    params.set('state', context.sessionId)
    params.set('response_uri', responseUri)
    params.set('dcql_query', JSON.stringify(context.dcql))
    if (clientMetadata !== undefined) {
      params.set('client_metadata', JSON.stringify(clientMetadata))
    }
    uri = `${scheme}://${DEEP_LINK_AUTHORITY}?${params.toString()}`
  }

  await storeRecord(context, channel, {
    state: context.sessionId,
    responseUri,
    clientId,
    ...(ephemeralPrivateJwk !== undefined ? { ephemeralPrivateJwk } : {}),
    ...(jar !== undefined ? { jar } : {}),
    ...(successRedirectTemplate !== undefined ? { successRedirectTemplate } : {}),
  })

  // direct_post.jwt arrives as a lone `response` JWE with no clear-text state, so the response
  // endpoint resolves the session through the key id the response was encrypted to.
  if (ephemeralPrivateJwk !== undefined && typeof ephemeralPrivateJwk.kid === 'string') {
    const index: JweKidIndexRecord = { v: 1, sessionId: context.sessionId }
    await context.config.session.set(
      `${JWE_KID_KEY_PREFIX}${ephemeralPrivateJwk.kid}`,
      index,
      context.ttlSeconds
    )
  }

  if (channel === 'qr') {
    return {
      channel: 'qr',
      sessionId: context.sessionId,
      qrPayload: uri,
      ...(requestUri !== undefined ? { requestUri } : {}),
      expiresAt: context.expiresAt,
    }
  }
  return {
    channel: 'deep-link',
    sessionId: context.sessionId,
    deepLink: uri,
    ...(requestUri !== undefined ? { requestUri } : {}),
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
    expiresAt: context.expiresAt.toISOString(),
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

/**
 * `request_uri` transport serves a *signed* Request Object, so by-reference is only reachable
 * from signed flows; it is also their default, because it keeps the QR/deep-link URI short.
 * Unsigned requests (the whole `'av'` profile) stay by value.
 */
function resolveJarMode(
  value: unknown,
  material: SignedRequestMaterial | null
): 'by-value' | 'by-reference' {
  if (value !== undefined && value !== 'by-value' && value !== 'by-reference') {
    invalid(`options.jarMode must be 'by-value' or 'by-reference', got ${JSON.stringify(value)}`)
  }
  const mode = value ?? (material === null ? 'by-value' : 'by-reference')
  if (mode === 'by-reference' && material === null) {
    invalid(
      "jarMode 'by-reference' serves a signed Request Object from request_uri, so it needs " +
        'a signed request: set signedRequest: true (with an x509_* prefix and signing keys) ' +
        "or use jarMode 'by-value'"
    )
  }
  return mode
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
