/**
 * `verifier.requests.create()` — the request-production pipeline.
 *
 * Four properties carry the security weight and get the densest coverage here:
 *
 *  - the profile × channel matrix fails loud (AV wallet + DC API can only produce an empty
 *    credential picker, so the SDK refuses to build the request at all);
 *  - unsigned DC API requests carry NO `client_id` and the ephemeral private key never appears
 *    in any output — only in the session record;
 *  - the by-value QR/deep-link URI round-trips: what a wallet decodes is byte-for-byte the
 *    query we were asked to send, with `state` carrying the session id;
 *  - every request gets fresh entropy, and the session record has the exact versioned shape the
 *    response phase will consume.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, presets } from '../src/index.js'
import type {
  Channel,
  CreatedRequest,
  DcqlQuery,
  Jwk,
  SessionAdapter,
  VerifierConfig,
} from '../src/types.js'
import { expectEudikitError } from './support.js'

const FIXED_NOW = new Date('2026-07-27T12:00:00.000Z')
const BASE64URL = /^[A-Za-z0-9_-]+$/

const agePreset = presets.age()

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.stubEnv('EUDIKIT_PUBLIC_BASE_URL', '')
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
})

interface CapturedSet {
  key: string
  record: Record<string, unknown>
  ttlSeconds: number
}

function captureAdapter(): { adapter: SessionAdapter; sets: CapturedSet[] } {
  const sets: CapturedSet[] = []
  return {
    adapter: {
      async set(key, record, ttlSeconds) {
        sets.push({ key, record, ttlSeconds })
      },
      async consume() {
        return null
      },
      async get() {
        return null
      },
      async delete() {},
    },
    sets,
  }
}

/** Verifier with a public base URL — the QR/deep-link happy path. */
function makeVerifier(overrides: Partial<VerifierConfig> = {}) {
  const { adapter, sets } = captureAdapter()
  const verifier = createVerifier({
    profile: 'av',
    publicBaseUrl: 'https://av-demo.example',
    session: adapter,
    now: () => FIXED_NOW,
    ...overrides,
  })
  return { verifier, sets }
}

/** Verifier without a public base URL — the DC API / localhost story. */
function makeBareVerifier(overrides: Partial<VerifierConfig> = {}) {
  const { adapter, sets } = captureAdapter()
  const verifier = createVerifier({
    profile: 'av',
    session: adapter,
    now: () => FIXED_NOW,
    ...overrides,
  })
  return { verifier, sets }
}

function lastSet(sets: CapturedSet[]): CapturedSet {
  const entry = sets[sets.length - 1]
  if (entry === undefined) throw new Error('expected a session record to have been written')
  return entry
}

function asDcApi(created: CreatedRequest): Extract<CreatedRequest, { channel: 'dc-api' }> {
  if (created.channel !== 'dc-api') throw new Error('expected a dc-api request')
  return created
}

function asQr(created: CreatedRequest): Extract<CreatedRequest, { channel: 'qr' }> {
  if (created.channel !== 'qr') throw new Error('expected a qr request')
  return created
}

function asDeepLink(created: CreatedRequest): Extract<CreatedRequest, { channel: 'deep-link' }> {
  if (created.channel !== 'deep-link') throw new Error('expected a deep-link request')
  return created
}

function queryParams(uri: string): URLSearchParams {
  const index = uri.indexOf('?')
  if (index === -1) throw new Error(`expected a query string in ${uri}`)
  return new URLSearchParams(uri.slice(index + 1))
}

// ---------------------------------------------------------------------------
// Error matrix
// ---------------------------------------------------------------------------

describe('requests.create — profile × channel guard', () => {
  it("throws CHANNEL_PROFILE_MISMATCH for profile 'av' + channel 'dc-api'", async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'dc-api' }),
      'CHANNEL_PROFILE_MISMATCH'
    )
    expect(error.message).toContain('org-iso-mdoc')
    expect(error.message).toContain("'deep-link' or 'qr'")
  })

  it('applies the guard to a per-request profile override as well', async () => {
    const { verifier } = makeBareVerifier({ profile: 'eudi' })
    await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'dc-api', profile: 'av' }),
      'CHANNEL_PROFILE_MISMATCH'
    )
  })
})

describe('requests.create — preset XOR dcql', () => {
  it('rejects both preset and dcql', async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.requests.create({
          preset: agePreset,
          dcql: agePreset.dcql,
          channel: 'deep-link',
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('not both')
  })

  it('rejects neither preset nor dcql', async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () => verifier.requests.create({ channel: 'deep-link' }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('preset')
    expect(error.message).toContain('dcql')
  })

  it('rejects a dcql query without a credentials array', async () => {
    const { verifier } = makeVerifier()
    await expectEudikitError(
      () =>
        verifier.requests.create({
          dcql: { note: 'no credentials' } as unknown as DcqlQuery,
          channel: 'deep-link',
        }),
      'CONFIG_INVALID'
    )
  })

  it('rejects an unknown channel value', async () => {
    const { verifier } = makeVerifier()
    await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'sms' as Channel }),
      'CONFIG_INVALID'
    )
  })
})

describe('requests.create — public base URL preconditions', () => {
  it('throws CONFIG_PUBLIC_BASE_URL_REQUIRED with the tunnel hint when nothing is configured', async () => {
    const { verifier } = makeBareVerifier()
    const error = await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'deep-link' }),
      'CONFIG_PUBLIC_BASE_URL_REQUIRED'
    )
    expect(error.message).toContain('DC API flow works on localhost')
    expect(error.message).toContain('cloudflared tunnel --url http://localhost:3000')
  })

  it('throws CONFIG_PUBLIC_BASE_URL_REQUIRED for a localhost base URL', async () => {
    const { verifier } = makeVerifier({ publicBaseUrl: 'https://localhost:3000' })
    const error = await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'qr' }),
      'CONFIG_PUBLIC_BASE_URL_REQUIRED'
    )
    expect(error.message).toContain('localhost')
  })

  it('throws CONFIG_PUBLIC_BASE_URL_NOT_HTTPS for a plain-http base URL', async () => {
    const { verifier } = makeVerifier({ publicBaseUrl: 'http://av-demo.example' })
    await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'deep-link' }),
      'CONFIG_PUBLIC_BASE_URL_NOT_HTTPS'
    )
  })

  it('falls back to the EUDIKIT_PUBLIC_BASE_URL env var', async () => {
    vi.stubEnv('EUDIKIT_PUBLIC_BASE_URL', 'https://tunnel.example')
    const { verifier } = makeBareVerifier()
    const created = asDeepLink(
      await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    )
    const params = queryParams(created.deepLink)
    expect(params.get('response_uri')).toBe('https://tunnel.example/api/eudikit/wallet/response')
  })
})

describe('requests.create — per-request option validation', () => {
  it('validates per-request expectedOrigins', async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.requests.create({
          preset: agePreset,
          channel: 'deep-link',
          expectedOrigins: ['https://shop.example/path'],
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('options.expectedOrigins[0]')
  })

  it("rejects encryptResponse: true under the 'av' profile", async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.requests.create({
          preset: agePreset,
          channel: 'deep-link',
          encryptResponse: true,
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('Annex A')
    expect(error.message).toContain('direct_post')
  })

  it('rejects a malformed scheme', async () => {
    const { verifier } = makeVerifier()
    await expectEudikitError(
      () =>
        verifier.requests.create({
          preset: agePreset,
          channel: 'deep-link',
          scheme: 'not a scheme',
        }),
      'CONFIG_INVALID'
    )
  })

  it('rejects an empty nonce override', async () => {
    const { verifier } = makeVerifier()
    await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'deep-link', nonce: '' }),
      'CONFIG_INVALID'
    )
  })
})

describe('requests.create — signing × prefix × transport rules', () => {
  it("rejects the 'eudi' qr/deep-link default (signed) under the redirect_uri prefix", async () => {
    // profile 'eudi' defaults QR/deep-link to a signed request, and the default prefix
    // cannot sign (OpenID4VP 1.0 §5.10) — the error must point at both ways out.
    const { verifier } = makeVerifier({ profile: 'eudi' })
    for (const channel of ['qr', 'deep-link'] as const) {
      const error = await expectEudikitError(
        () => verifier.requests.create({ preset: agePreset, channel }),
        'CONFIG_INVALID'
      )
      expect(error.message).toContain('redirect_uri')
      expect(error.message).toContain('§5.10')
      expect(error.message).toContain('signedRequest: false')
    }
  })

  it('rejects an explicit signedRequest: true with the redirect_uri prefix on any channel', async () => {
    const av = makeVerifier()
    const eudi = makeBareVerifier({ profile: 'eudi' })
    for (const [verifier, channel] of [
      [av.verifier, 'deep-link'],
      [eudi.verifier, 'dc-api'],
    ] as const) {
      const error = await expectEudikitError(
        () => verifier.requests.create({ preset: agePreset, channel, signedRequest: true }),
        'CONFIG_INVALID'
      )
      expect(error.message).toContain('redirect_uri')
    }
  })

  it("rejects jarMode 'by-reference' on an unsigned request", async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () => verifier.requests.create({ preset: agePreset, channel: 'qr', jarMode: 'by-reference' }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('signed Request Object')
  })

  it("builds 'eudi' unsigned direct_post with direct_post.jwt encryption by default", async () => {
    const { verifier } = makeVerifier({ profile: 'eudi' })
    const created = await verifier.requests.create({
      preset: agePreset,
      channel: 'deep-link',
      signedRequest: false,
    })
    if (created.channel !== 'deep-link') throw new Error('expected deep-link')
    const params = new URLSearchParams(created.deepLink.slice(created.deepLink.indexOf('?') + 1))
    expect(params.get('response_mode')).toBe('direct_post.jwt')
    const metadata = JSON.parse(params.get('client_metadata') ?? '{}') as {
      jwks?: { keys?: Array<Record<string, unknown>> }
      encrypted_response_enc_values_supported?: string[]
    }
    expect(metadata.encrypted_response_enc_values_supported).toEqual(['A128GCM'])
    const key = metadata.jwks?.keys?.[0]
    expect(key?.kty).toBe('EC')
    // The published half is public: no private scalar anywhere in the emitted URI.
    expect(created.deepLink).not.toContain('%22d%22')
  })

  it('requires signing keys for the x509 client id prefixes', async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.requests.create({
          preset: agePreset,
          channel: 'deep-link',
          clientIdPrefix: 'x509_san_dns',
        }),
      'CONFIG_SIGNING_KEY_REQUIRED'
    )
    expect(error.message).toContain('keys.requestSigning')
  })

  it('rejects an x509 prefix combined with signedRequest: false as contradictory', async () => {
    const { verifier } = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.requests.create({
          preset: agePreset,
          channel: 'deep-link',
          clientIdPrefix: 'x509_hash',
          signedRequest: false,
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('signed request object')
  })
})

// ---------------------------------------------------------------------------
// channel 'dc-api'
// ---------------------------------------------------------------------------

describe("requests.create — channel 'dc-api' (profile 'eudi', unsigned)", () => {
  it('works without any public base URL — the localhost DX promise', async () => {
    const { verifier } = makeBareVerifier({ profile: 'eudi' })
    const created = asDcApi(
      await verifier.requests.create({ preset: agePreset, channel: 'dc-api' })
    )
    expect(created.dcApiRequest.protocol).toBe('openid4vp-v1-unsigned')
  })

  it('emits the encrypted dc_api.jwt shape with NO client_id anywhere', async () => {
    const { verifier } = makeBareVerifier({ profile: 'eudi' })
    const created = asDcApi(
      await verifier.requests.create({ preset: agePreset, channel: 'dc-api' })
    )
    const { data } = created.dcApiRequest

    expect(Object.keys(data).sort()).toEqual([
      'client_metadata',
      'dcql_query',
      'nonce',
      'response_mode',
      'response_type',
    ])
    expect(data.response_type).toBe('vp_token')
    expect(data.response_mode).toBe('dc_api.jwt')
    expect(data.dcql_query).toEqual(agePreset.dcql)

    const meta = data.client_metadata as {
      jwks: { keys: Array<Record<string, unknown>> }
      encrypted_response_enc_values_supported: string[]
    }
    expect(meta.encrypted_response_enc_values_supported).toEqual(['A128GCM'])
    expect(meta.jwks.keys).toHaveLength(1)
  })

  it('publishes a P-256 public key and never leaks the private half', async () => {
    const { verifier, sets } = makeBareVerifier({ profile: 'eudi' })
    const created = asDcApi(
      await verifier.requests.create({ preset: agePreset, channel: 'dc-api' })
    )
    const meta = created.dcApiRequest.data.client_metadata as {
      jwks: { keys: Array<Record<string, unknown>> }
    }
    const publicJwk = meta.jwks.keys[0]
    if (publicJwk === undefined) throw new Error('expected a published JWK')

    expect(publicJwk.kty).toBe('EC')
    expect(publicJwk.crv).toBe('P-256')
    expect(publicJwk.use).toBe('enc')
    expect(publicJwk.alg).toBe('ECDH-ES')
    expect(typeof publicJwk.x).toBe('string')
    expect(typeof publicJwk.y).toBe('string')
    expect(typeof publicJwk.kid).toBe('string')
    // The regression that must never ship: a private parameter in the published key.
    expect(Object.keys(publicJwk)).not.toContain('d')

    const record = lastSet(sets).record
    const privateJwk = record.ephemeralPrivateJwk as Jwk
    expect(typeof privateJwk.d).toBe('string')
    expect(privateJwk.kid).toBe(publicJwk.kid)
    expect(JSON.stringify(created)).not.toContain(privateJwk.d as string)
  })

  it('generates a base64url nonce of at least 16 bytes', async () => {
    const { verifier } = makeBareVerifier({ profile: 'eudi' })
    const created = asDcApi(
      await verifier.requests.create({ preset: agePreset, channel: 'dc-api' })
    )
    const nonce = created.dcApiRequest.data.nonce as string
    expect(nonce).toMatch(BASE64URL)
    // 16 bytes encode to 22 base64url characters; the SDK generates 32 bytes (43 characters).
    expect(nonce.length).toBeGreaterThanOrEqual(22)
  })

  it('honors a nonce override', async () => {
    const { verifier, sets } = makeBareVerifier({ profile: 'eudi' })
    const created = asDcApi(
      await verifier.requests.create({
        preset: agePreset,
        channel: 'dc-api',
        nonce: 'fixed-test-nonce',
      })
    )
    expect(created.dcApiRequest.data.nonce).toBe('fixed-test-nonce')
    expect(lastSet(sets).record.nonce).toBe('fixed-test-nonce')
  })

  it("writes the versioned session record under 'request:{sessionId}'", async () => {
    const { verifier, sets } = makeBareVerifier({
      profile: 'eudi',
      expectedOrigins: ['https://shop.example'],
    })
    const created = asDcApi(
      await verifier.requests.create({ preset: agePreset, channel: 'dc-api' })
    )
    const { key, record, ttlSeconds } = lastSet(sets)

    expect(key).toBe(`request:${created.sessionId}`)
    expect(ttlSeconds).toBe(900)
    expect(Object.keys(record).sort()).toEqual([
      'channel',
      'createdAt',
      'dcql',
      'ephemeralPrivateJwk',
      'expectedOrigins',
      'expiresAt',
      'nonce',
      'presetId',
      'profile',
      'v',
    ])
    expect(record.v).toBe(1)
    expect(record.presetId).toMatch(/^age#/)
    expect(record.profile).toBe('eudi')
    expect(record.channel).toBe('dc-api')
    expect(record.dcql).toEqual(agePreset.dcql)
    expect(record.expectedOrigins).toEqual(['https://shop.example'])
    expect(record.createdAt).toBe(FIXED_NOW.toISOString())
  })

  it('switches to plain dc_api without a key when encryptResponse is false', async () => {
    const { verifier, sets } = makeBareVerifier({ profile: 'eudi' })
    const created = asDcApi(
      await verifier.requests.create({
        preset: agePreset,
        channel: 'dc-api',
        encryptResponse: false,
      })
    )
    const { data } = created.dcApiRequest
    expect(data.response_mode).toBe('dc_api')
    expect(Object.keys(data).sort()).toEqual([
      'dcql_query',
      'nonce',
      'response_mode',
      'response_type',
    ])
    expect(lastSet(sets).record).not.toHaveProperty('ephemeralPrivateJwk')
  })
})

// ---------------------------------------------------------------------------
// channels 'qr' | 'deep-link'
// ---------------------------------------------------------------------------

describe("requests.create — channels 'qr' and 'deep-link' (profile 'av', by-value)", () => {
  it('builds a deep link that decodes back to exactly what we asked for', async () => {
    const { verifier, sets } = makeVerifier()
    const created = asDeepLink(
      await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    )

    // The `authorize` authority is load-bearing: the AV wallet's Android intent filter is
    // registered with host `authorize`, so a bare `scheme://?…` URI never matches there.
    expect(created.deepLink.startsWith('eudi-openid4vp://authorize?')).toBe(true)
    expect(created.requestUri).toBeUndefined()

    const params = queryParams(created.deepLink)
    expect([...params.keys()].sort()).toEqual([
      'client_id',
      'dcql_query',
      'nonce',
      'response_mode',
      'response_type',
      'response_uri',
      'state',
    ])

    const responseUri = 'https://av-demo.example/api/eudikit/wallet/response'
    expect(params.get('response_uri')).toBe(responseUri)
    expect(params.get('client_id')).toBe(`redirect_uri:${responseUri}`)
    expect(params.get('response_type')).toBe('vp_token')
    expect(params.get('response_mode')).toBe('direct_post')
    expect(params.get('state')).toBe(created.sessionId)
    expect(params.get('nonce')).toBe(lastSet(sets).record.nonce)
    expect(JSON.parse(params.get('dcql_query') ?? '')).toEqual(agePreset.dcql)
  })

  it('returns the same by-value URI as qrPayload on the qr channel', async () => {
    const { verifier } = makeVerifier()
    const created = asQr(await verifier.requests.create({ preset: agePreset, channel: 'qr' }))
    expect(created.qrPayload.startsWith('eudi-openid4vp://authorize?')).toBe(true)
    expect(created.requestUri).toBeUndefined()
    expect(queryParams(created.qrPayload).get('state')).toBe(created.sessionId)
  })

  it('honors a scheme override', async () => {
    const { verifier } = makeVerifier()
    const created = asDeepLink(
      await verifier.requests.create({ preset: agePreset, channel: 'deep-link', scheme: 'av' })
    )
    expect(created.deepLink.startsWith('av://authorize?')).toBe(true)
  })

  it('derives the response_uri from routeBasePath, normalizing slashes', async () => {
    const { verifier } = makeVerifier({ routeBasePath: 'custom/mount/' })
    const created = asDeepLink(
      await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    )
    expect(queryParams(created.deepLink).get('response_uri')).toBe(
      'https://av-demo.example/custom/mount/wallet/response'
    )
  })

  it('writes the direct_post session record with state = sessionId and no ephemeral key', async () => {
    const { verifier, sets } = makeVerifier()
    const created = asDeepLink(
      await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    )
    const { key, record, ttlSeconds } = lastSet(sets)

    expect(key).toBe(`request:${created.sessionId}`)
    expect(ttlSeconds).toBe(900)
    expect(Object.keys(record).sort()).toEqual([
      'channel',
      'clientId',
      'createdAt',
      'dcql',
      'expectedOrigins',
      'expiresAt',
      'nonce',
      'presetId',
      'profile',
      'responseUri',
      'state',
      'v',
    ])
    expect(record.clientId).toBe('redirect_uri:https://av-demo.example/api/eudikit/wallet/response')
    expect(record.v).toBe(1)
    expect(record.state).toBe(created.sessionId)
    expect(record.responseUri).toBe('https://av-demo.example/api/eudikit/wallet/response')
    expect(record.profile).toBe('av')
    expect(record.channel).toBe('deep-link')
    expect(record.createdAt).toBe(FIXED_NOW.toISOString())
  })

  it('stores a per-request expectedOrigins override in the record', async () => {
    const { verifier, sets } = makeVerifier({ expectedOrigins: ['https://config.example'] })
    await verifier.requests.create({
      preset: agePreset,
      channel: 'deep-link',
      expectedOrigins: ['https://override.example'],
    })
    expect(lastSet(sets).record.expectedOrigins).toEqual(['https://override.example'])
  })

  it("lets 'eudi' opt down to the unsigned, unencrypted flow — profile is defaults, not a lock", async () => {
    const { verifier, sets } = makeVerifier({ profile: 'eudi' })
    const created = asDeepLink(
      await verifier.requests.create({
        preset: agePreset,
        channel: 'deep-link',
        signedRequest: false,
        encryptResponse: false,
      })
    )
    expect(queryParams(created.deepLink).get('response_mode')).toBe('direct_post')
    expect(lastSet(sets).record.profile).toBe('eudi')
  })

  it('passes a raw dcql query through verbatim, extension properties included', async () => {
    const dcql: DcqlQuery = {
      credentials: [
        {
          id: 'custom_age',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.av.1' },
          claims: [{ path: ['eu.europa.ec.av.1', 'age_over_18'], intent_to_retain: false }],
        },
      ],
      vendor_extension: { keep: true },
    }
    const { verifier } = makeVerifier()
    const created = asDeepLink(await verifier.requests.create({ dcql, channel: 'deep-link' }))
    expect(JSON.parse(queryParams(created.deepLink).get('dcql_query') ?? '')).toEqual(dcql)
  })
})

// ---------------------------------------------------------------------------
// Entropy and time
// ---------------------------------------------------------------------------

describe('requests.create — entropy and time', () => {
  it('generates fresh nonce and sessionId on every call', async () => {
    const { verifier, sets } = makeVerifier()
    const first = asDeepLink(
      await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    )
    const firstNonce = lastSet(sets).record.nonce
    const second = asDeepLink(
      await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    )
    const secondNonce = lastSet(sets).record.nonce

    expect(second.sessionId).not.toBe(first.sessionId)
    expect(secondNonce).not.toBe(firstNonce)
  })

  it('uses base64url session ids long enough for 32 bytes of entropy', async () => {
    const { verifier } = makeVerifier()
    const created = await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    expect(created.sessionId).toMatch(BASE64URL)
    expect(created.sessionId.length).toBeGreaterThanOrEqual(43)
  })

  it('computes expiresAt deterministically from the injected clock', async () => {
    const { verifier } = makeVerifier()
    const created = await verifier.requests.create({ preset: agePreset, channel: 'deep-link' })
    expect(created.expiresAt.getTime()).toBe(FIXED_NOW.getTime() + 900_000)
  })

  it('honors a per-request ttlSeconds in both expiresAt and the stored TTL', async () => {
    const { verifier, sets } = makeVerifier()
    const created = await verifier.requests.create({
      preset: agePreset,
      channel: 'deep-link',
      ttlSeconds: 300,
    })
    expect(created.expiresAt.getTime()).toBe(FIXED_NOW.getTime() + 300_000)
    expect(lastSet(sets).ttlSeconds).toBe(300)
  })
})
