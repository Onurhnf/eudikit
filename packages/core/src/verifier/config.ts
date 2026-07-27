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

import { notImplemented } from '../internal/not-implemented.js'
import { memorySessionAdapter } from '../session/memory.js'
import type { ClientIdPrefix, SessionAdapter, VerifierConfig, WalletProfile } from '../types.js'
import { EudikitError } from '../types.js'
import { toDerCertificates } from '../verify/certificates.js'
import type { ResolvedTrust } from '../verify/engine.js'

export interface ResolvedVerifierConfig {
  profile: WalletProfile
  clientIdPrefix: ClientIdPrefix
  /** Normalized (no trailing slash); `null` when neither config nor env provides one. */
  publicBaseUrl: string | null
  /** Normalized: leading slash, no trailing slash; `''` when mounted at the root. */
  routeBasePath: string
  session: SessionAdapter
  expectedOrigins: string[]
  requestTtlSeconds: number
  resultTtlSeconds: number
  trust: ResolvedTrust
  now: () => Date
}

const PUBLIC_BASE_URL_ENV = 'EUDIKIT_PUBLIC_BASE_URL'

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

  return {
    profile: validateProfile(config.profile, 'config.profile'),
    clientIdPrefix:
      config.clientIdPrefix === undefined
        ? 'redirect_uri'
        : validateClientIdPrefix(config.clientIdPrefix, 'config.clientIdPrefix'),
    publicBaseUrl: resolvePublicBaseUrl(config.publicBaseUrl),
    routeBasePath: resolveRouteBasePath(config.routeBasePath),
    session: resolveSession(config.session),
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
    trust: resolveTrust(config.trust),
    now: config.now ?? (() => new Date()),
  }
}

/**
 * Trusted-list fetching is not built yet, and pretending otherwise would verify against nothing:
 * an explicitly enabled `avTrustedList` fails loud instead of being silently ignored. When the
 * option is omitted, verification uses `additionalTrustAnchors` only (DS-direct-match); the
 * trusted-list layer is the next phase, and the default flips to the EU AV list once it exists.
 */
function resolveTrust(trust: VerifierConfig['trust']): ResolvedTrust {
  if (trust === undefined) return { mode: 'strict', anchors: [] }
  if (typeof trust !== 'object' || trust === null) {
    invalid('config.trust must be a TrustConfig object')
  }

  const mode = trust.mode ?? 'strict'
  if (mode !== 'strict' && mode !== 'permissive') {
    invalid(`config.trust.mode must be 'strict' or 'permissive', got ${JSON.stringify(mode)}`)
  }

  if (trust.avTrustedList !== undefined && trust.avTrustedList !== false) {
    notImplemented('AV trusted list fetching (trust.avTrustedList)')
  }

  const anchors = (trust.additionalTrustAnchors ?? []).flatMap((anchor, index) =>
    toDerCertificates(anchor, `config.trust.additionalTrustAnchors[${index}]`)
  )
  return { mode, anchors }
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
