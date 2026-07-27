/**
 * Resolution and validation of `VerifierConfig` into the internal shape the request builders
 * consume.
 *
 * The split between fail-now and fail-later is deliberate: values that can never be right for
 * any channel (a malformed URL, a bad origin string, a reserved option) throw at
 * `createVerifier()` time, while values that are only wrong for *some* channels — a missing or
 * unreachable `publicBaseUrl` — are checked when a request for such a channel is created. A
 * DC-API-only verifier therefore keeps working on localhost with zero public infrastructure.
 */

import {
  createHash,
  createPrivateKey,
  type JsonWebKey,
  type KeyObject,
  X509Certificate,
} from 'node:crypto'
import { memorySessionAdapter } from '../session/memory.js'
import {
  memoryTrustCache,
  sessionAdapterTrustCache,
  TrustedListSource,
} from '../trust/trusted-list.js'
import type {
  ClientIdPrefix,
  SessionAdapter,
  TrustCacheAdapter,
  VerifierConfig,
  VerifierKeys,
  WalletProfile,
} from '../types.js'
import { EudikitError } from '../types.js'
import { toDerCertificates } from '../verify/certificates.js'
import type { ResolvedTrust } from '../verify/engine.js'

export type SigningAlgorithm = 'ES256' | 'ES384' | 'ES512'

export interface ResolvedSigningKeys {
  /** JAR signing key, resolved to a live key object; `null` when neither config nor env has one. */
  signing: { key: KeyObject; alg: SigningAlgorithm } | null
  /** x5c chain, leaf first. Empty when not configured. */
  chainDer: Uint8Array[]
  /** The same chain as standard base64 (the `x5c` header encoding). */
  chainB64: string[]
  /** dNSName SAN entries of the leaf — the valid `x509_san_dns` original client ids. */
  sanDnsNames: string[]
  /** base64url(SHA-256(leaf DER)) — the `x509_hash` original client id. `null` without a chain. */
  x509HashClientId: string | null
}

export interface ResolvedVerifierConfig {
  profile: WalletProfile
  clientIdPrefix: ClientIdPrefix
  /** Original client id for the `x509_*` prefixes; `null` when not configured. */
  clientId: string | null
  /** Normalized (no trailing slash); `null` when neither config nor env provides one. */
  publicBaseUrl: string | null
  /** Normalized: leading slash, no trailing slash; `''` when mounted at the root. */
  routeBasePath: string
  session: SessionAdapter
  keys: ResolvedSigningKeys
  expectedOrigins: string[]
  requestTtlSeconds: number
  resultTtlSeconds: number
  trust: ResolvedTrust
  fetch: typeof fetch
  now: () => Date
}

const PUBLIC_BASE_URL_ENV = 'EUDIKIT_PUBLIC_BASE_URL'
const SIGNING_KEY_ENV = 'EUDIKIT_SIGNING_KEY'

/** Today's only live list; the default changes when a production list is published. */
export const DEFAULT_AV_TRUSTED_LIST_URL =
  'https://acceptance.trust.tech.ec.europa.eu/lists/age-verification/av-tl.xml'

const TUNNEL_HINT =
  'cross-device flows need a publicly reachable HTTPS base URL — the DC API flow works on ' +
  'localhost; use e.g. `cloudflared tunnel --url http://localhost:3000` during development'

function invalid(detail: string): never {
  throw new EudikitError('CONFIG_INVALID', detail)
}

export function resolveVerifierConfig(config: VerifierConfig): ResolvedVerifierConfig {
  if (typeof config !== 'object' || config === null) {
    invalid('createVerifier(config) needs a config object')
  }

  if (config.protocolAdapters !== undefined && config.protocolAdapters.length > 0) {
    throw new EudikitError(
      'CONFIG_UNSUPPORTED_ADAPTER',
      'protocolAdapters is a reserved extension point: no protocol adapter ships in v1, so the ' +
        'configured adapters would silently do nothing. Remove them for now — the first ' +
        'supported adapter (org-iso-mdoc, ISO 18013-7 Annex C) is planned for v1.1.'
    )
  }

  const session = resolveSession(config.session)
  const fetchImpl = resolveFetch(config.fetch)

  return {
    profile: validateProfile(config.profile, 'config.profile'),
    clientIdPrefix:
      config.clientIdPrefix === undefined
        ? 'redirect_uri'
        : validateClientIdPrefix(config.clientIdPrefix, 'config.clientIdPrefix'),
    clientId: resolveClientId(config.clientId),
    publicBaseUrl: resolvePublicBaseUrl(config.publicBaseUrl),
    routeBasePath: resolveRouteBasePath(config.routeBasePath),
    session,
    keys: resolveKeys(config.keys),
    expectedOrigins:
      config.expectedOrigins === undefined
        ? []
        : validateExpectedOrigins(config.expectedOrigins, 'config.expectedOrigins'),
    requestTtlSeconds: validateTtlSeconds(
      config.requestTtlSeconds,
      'config.requestTtlSeconds',
      900
    ),
    resultTtlSeconds: validateTtlSeconds(config.resultTtlSeconds, 'config.resultTtlSeconds', 600),
    trust: resolveTrust(config.trust, session, fetchImpl),
    fetch: fetchImpl,
    now: config.now ?? (() => new Date()),
  }
}

/**
 * The AV trusted list is ON by default: omitting `avTrustedList` (or passing `true`) verifies
 * against the EU list at its default URL, `false` switches the layer off, and an object
 * overrides URL, refresh cadence or cache. `additionalTrustAnchors` always apply on top —
 * union, not either/or.
 */
function resolveTrust(
  trust: VerifierConfig['trust'],
  session: SessionAdapter,
  fetchImpl: typeof fetch
): ResolvedTrust {
  if (trust !== undefined && (typeof trust !== 'object' || trust === null)) {
    invalid('config.trust must be a TrustConfig object')
  }

  const mode = trust?.mode ?? 'strict'
  if (mode !== 'strict' && mode !== 'permissive') {
    invalid(`config.trust.mode must be 'strict' or 'permissive', got ${JSON.stringify(mode)}`)
  }

  const anchors = (trust?.additionalTrustAnchors ?? []).flatMap((anchor, index) =>
    toDerCertificates(anchor, `config.trust.additionalTrustAnchors[${index}]`)
  )

  const listConfig = trust?.avTrustedList
  if (listConfig === false) {
    return { mode, anchors, trustedList: null }
  }

  let url = DEFAULT_AV_TRUSTED_LIST_URL
  let refreshIntervalSeconds = 3600
  if (listConfig !== undefined && listConfig !== true) {
    if (typeof listConfig !== 'object' || listConfig === null) {
      invalid('config.trust.avTrustedList must be a boolean or an options object')
    }
    if (listConfig.url !== undefined) {
      if (typeof listConfig.url !== 'string' || parseUrl(listConfig.url) === null) {
        invalid('config.trust.avTrustedList.url must be an absolute URL')
      }
      url = listConfig.url
    }
    refreshIntervalSeconds = validateTtlSeconds(
      listConfig.refreshIntervalSeconds,
      'config.trust.avTrustedList.refreshIntervalSeconds',
      3600
    )
  }

  return {
    mode,
    anchors,
    trustedList: new TrustedListSource({
      url,
      refreshIntervalSeconds,
      cache: resolveTrustCache(trust?.cache, session),
      fetch: fetchImpl,
    }),
  }
}

function resolveTrustCache(
  cache: 'memory' | 'session-adapter' | TrustCacheAdapter | undefined,
  session: SessionAdapter
): TrustCacheAdapter {
  if (cache === undefined || cache === 'memory') return memoryTrustCache()
  if (cache === 'session-adapter') return sessionAdapterTrustCache(session)
  if (typeof cache === 'object' && cache !== null) {
    if (typeof cache.get !== 'function' || typeof cache.set !== 'function') {
      invalid('config.trust.cache adapter must provide get() and set()')
    }
    return cache
  }
  invalid(
    `config.trust.cache must be 'memory', 'session-adapter' or a TrustCacheAdapter, got ` +
      JSON.stringify(cache)
  )
}

// ---------------------------------------------------------------------------
// signing keys
// ---------------------------------------------------------------------------

const CURVE_TO_ALGORITHM: Record<string, SigningAlgorithm> = {
  prime256v1: 'ES256',
  'P-256': 'ES256',
  secp384r1: 'ES384',
  'P-384': 'ES384',
  secp521r1: 'ES512',
  'P-521': 'ES512',
}

/**
 * Resolves the JAR signing material once, at `createVerifier()` time, so that a malformed key
 * or a key/certificate mismatch fails at boot instead of on the first signed request. All
 * parsing is `node:crypto` — no certificate library, and the resolution is synchronous.
 */
function resolveKeys(keys: VerifierKeys | undefined): ResolvedSigningKeys {
  if (keys !== undefined && (typeof keys !== 'object' || keys === null)) {
    invalid('config.keys must be a VerifierKeys object')
  }

  const signing = resolveSigningKey(keys?.requestSigning)

  const chainDer = (keys?.requestSigningCertificateChain ?? []).flatMap((certificate, index) =>
    toDerCertificates(certificate, `config.keys.requestSigningCertificateChain[${index}]`)
  )
  let sanDnsNames: string[] = []
  let x509HashClientId: string | null = null
  const leafDer = chainDer[0]
  if (leafDer !== undefined) {
    let leaf: X509Certificate
    try {
      leaf = new X509Certificate(leafDer)
    } catch (cause) {
      invalidWithCause(
        'config.keys.requestSigningCertificateChain[0] is not a parseable X.509 certificate',
        cause
      )
    }
    sanDnsNames = dnsNamesOf(leaf)
    x509HashClientId = createHash('sha256').update(leafDer).digest('base64url')
    if (signing !== null && !leaf.checkPrivateKey(signing.key)) {
      invalid(
        'keys.requestSigning does not match the public key of ' +
          'keys.requestSigningCertificateChain[0] — the wallet would reject every signed request'
      )
    }
  }

  return {
    signing,
    chainDer,
    chainB64: chainDer.map((der) => Buffer.from(der).toString('base64')),
    sanDnsNames,
    x509HashClientId,
  }
}

function resolveSigningKey(
  requestSigning: VerifierKeys['requestSigning']
): ResolvedSigningKeys['signing'] {
  let key: KeyObject
  let declaredAlg: string | undefined

  if (requestSigning === undefined) {
    const pem = globalThis.process?.env?.[SIGNING_KEY_ENV]
    if (typeof pem !== 'string' || pem === '') return null
    try {
      key = createPrivateKey(pem)
    } catch (cause) {
      invalidWithCause(`the ${SIGNING_KEY_ENV} env var is not a parseable PKCS#8 PEM key`, cause)
    }
  } else if ('jwk' in requestSigning) {
    const jwk = requestSigning.jwk
    if (typeof jwk !== 'object' || jwk === null) {
      invalid('keys.requestSigning.jwk must be a private JWK object')
    }
    declaredAlg = typeof jwk.alg === 'string' ? jwk.alg : undefined
    try {
      key = createPrivateKey({ key: jwk as JsonWebKey, format: 'jwk' })
    } catch (cause) {
      invalidWithCause('keys.requestSigning.jwk is not a parseable private JWK', cause)
    }
  } else {
    if (typeof requestSigning.pem !== 'string' || requestSigning.pem === '') {
      invalid('keys.requestSigning.pem must be a PKCS#8 PEM string')
    }
    declaredAlg = requestSigning.alg
    try {
      key = createPrivateKey(requestSigning.pem)
    } catch (cause) {
      invalidWithCause('keys.requestSigning.pem is not a parseable PKCS#8 PEM key', cause)
    }
  }

  if (key.asymmetricKeyType !== 'ec') {
    invalid(
      `the request signing key must be an EC P-256/P-384/P-521 key (ES256/ES384/ES512), got ` +
        `key type "${key.asymmetricKeyType ?? 'unknown'}"`
    )
  }
  const curve = key.asymmetricKeyDetails?.namedCurve ?? ''
  const alg = CURVE_TO_ALGORITHM[curve]
  if (alg === undefined) {
    invalid(`the request signing key uses unsupported curve "${curve}"`)
  }
  if (declaredAlg !== undefined && declaredAlg !== alg) {
    invalid(
      `keys.requestSigning declares alg "${declaredAlg}" but the key's curve (${curve}) ` +
        `requires ${alg}`
    )
  }
  return { key, alg }
}

/** `X509Certificate.subjectAltName` renders as `DNS:a.example, IP Address:…, …`. */
function dnsNamesOf(certificate: X509Certificate): string[] {
  const san = certificate.subjectAltName
  if (san === null || san === undefined) return []
  return san
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.startsWith('DNS:'))
    .map((entry) => entry.slice(4))
}

function resolveClientId(value: unknown): string | null {
  if (value === undefined) return null
  if (typeof value !== 'string' || value === '') {
    invalid('config.clientId must be a non-empty string')
  }
  return value
}

function resolveFetch(value: unknown): typeof fetch {
  if (value === undefined) return globalThis.fetch
  if (typeof value !== 'function') {
    invalid('config.fetch must be a fetch-compatible function')
  }
  return value as typeof fetch
}

function invalidWithCause(detail: string, cause: unknown): never {
  throw new EudikitError('CONFIG_INVALID', detail, { cause })
}

export function validateProfile(value: unknown, source: string): WalletProfile {
  if (value === 'av' || value === 'eudi') return value
  invalid(
    value === undefined
      ? `${source} is mandatory and has no default: pass 'av' (today's Age Verification wallet) ` +
          `or 'eudi' (EUDI wallets and the Digital Credentials API)`
      : `${source} must be 'av' or 'eudi', got ${JSON.stringify(value)}`
  )
}

export function validateClientIdPrefix(value: unknown, source: string): ClientIdPrefix {
  if (value === 'redirect_uri' || value === 'x509_san_dns' || value === 'x509_hash') return value
  invalid(
    `${source} must be 'redirect_uri', 'x509_san_dns' or 'x509_hash', got ${JSON.stringify(value)}`
  )
}

export function validateTtlSeconds(value: unknown, source: string, fallback: number): number {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0) {
    invalid(`${source} must be a positive integer number of seconds, got ${JSON.stringify(value)}`)
  }
  return value
}

/**
 * Both origin shapes are first class:
 *
 *  - a serialized web origin — `https://shop.example`, or `http://localhost:3000` for local
 *    development (browsers treat loopback as a trustworthy origin, and the DC API channel is
 *    exactly the one that runs there);
 *  - an Android app origin — `android:apk-key-hash:<base64url-nopad-sha256>`.
 */
export function validateExpectedOrigins(origins: readonly unknown[], source: string): string[] {
  if (!Array.isArray(origins)) invalid(`${source} must be an array of origin strings`)

  return origins.map((origin, index) => {
    const label = `${source}[${index}]`
    if (typeof origin !== 'string' || origin.length === 0) {
      invalid(`${label} must be a non-empty string`)
    }

    if (origin.startsWith(APK_KEY_HASH_PREFIX)) {
      const hash = origin.slice(APK_KEY_HASH_PREFIX.length)
      if (!BASE64URL_NOPAD.test(hash)) {
        invalid(
          `${label} "${origin}" has a malformed apk-key-hash: expected unpadded base64url ` +
            `(A-Z a-z 0-9 - _) after "${APK_KEY_HASH_PREFIX}"`
        )
      }
      return origin
    }

    const url = parseUrl(origin)
    if (url === null) {
      invalid(
        `${label} "${origin}" is neither a web origin (e.g. "https://shop.example") nor an ` +
          `"${APK_KEY_HASH_PREFIX}<base64url>" app origin`
      )
    }
    if (url.origin !== origin) {
      invalid(
        `${label} "${origin}" must be a serialized origin — scheme://host[:port] with no path, ` +
          `query, fragment or trailing slash (did you mean "${url.origin}"?)`
      )
    }
    const isDevHttp = url.protocol === 'http:' && isLoopbackHost(url.hostname)
    if (url.protocol !== 'https:' && !isDevHttp) {
      invalid(
        `${label} "${origin}" must use https — http origins are only accepted for localhost ` +
          `development`
      )
    }
    return origin
  })
}

/**
 * The QR/deep-link precondition: the wallet's phone must be able to reach us. Returns the
 * normalized base URL or throws the explanatory config error.
 */
export function requirePublicBaseUrl(
  config: ResolvedVerifierConfig,
  channel: 'qr' | 'deep-link'
): string {
  const base = config.publicBaseUrl
  if (base === null) {
    throw new EudikitError(
      'CONFIG_PUBLIC_BASE_URL_REQUIRED',
      `channel '${channel}' has no public base URL: set publicBaseUrl or the ` +
        `${PUBLIC_BASE_URL_ENV} env var. Note that ${TUNNEL_HINT}`
    )
  }

  const url = parseUrl(base)
  if (url === null) invalid(`publicBaseUrl "${base}" is not a valid URL`)

  if (isLoopbackHost(url.hostname)) {
    throw new EudikitError(
      'CONFIG_PUBLIC_BASE_URL_REQUIRED',
      `publicBaseUrl "${base}" is only reachable on this machine, not from the wallet's phone: ` +
        TUNNEL_HINT
    )
  }
  if (url.protocol !== 'https:') {
    throw new EudikitError(
      'CONFIG_PUBLIC_BASE_URL_NOT_HTTPS',
      `publicBaseUrl "${base}" must use https: wallets refuse to post credentials to a ` +
        `plain-http response endpoint`
    )
  }
  return base
}

const APK_KEY_HASH_PREFIX = 'android:apk-key-hash:'
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]+$/

function resolvePublicBaseUrl(configured: unknown): string | null {
  if (configured !== undefined && typeof configured !== 'string') {
    invalid('publicBaseUrl must be a string URL')
  }
  const raw =
    typeof configured === 'string' && configured !== '' ? configured : readEnvPublicBaseUrl()
  if (raw === null) return null

  if (parseUrl(raw) === null) {
    invalid(
      `publicBaseUrl "${raw}" is not a valid absolute URL — expected something like ` +
        `"https://verifier.example"`
    )
  }
  return raw.replace(/\/+$/, '')
}

function readEnvPublicBaseUrl(): string | null {
  const value = globalThis.process?.env?.[PUBLIC_BASE_URL_ENV]
  return typeof value === 'string' && value !== '' ? value : null
}

function resolveRouteBasePath(value: unknown): string {
  if (value === undefined) return '/api/eudikit'
  if (typeof value !== 'string') {
    invalid('routeBasePath must be a string path like "/api/eudikit"')
  }
  const trimmed = value.replace(/\/+$/, '')
  if (trimmed === '') return ''
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`
}

function resolveSession(value: SessionAdapter | undefined): SessionAdapter {
  if (value === undefined) return memorySessionAdapter()
  for (const method of ['set', 'consume', 'get', 'delete'] as const) {
    if (typeof value[method] !== 'function') {
      invalid(`session adapter is missing the ${method}() method`)
    }
  }
  return value
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase()
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '0.0.0.0' ||
    host === '[::1]' ||
    host === '127.0.0.1' ||
    host.startsWith('127.')
  )
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value)
  } catch {
    return null
  }
}
