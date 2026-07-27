/**
 * End-to-end tests of the QR/deep-link response flow — the one flow today's AV wallet can
 * actually complete: `requests.create` → wallet simulation (a real `DeviceResponse` signed
 * over the rebuilt SessionTranscript) → form POST to `handleWalletResponse` → `getResult`.
 *
 * The wallet side uses the same issuance APIs as `@owf/mdoc`'s own tests, so a green run here
 * means real CBOR, real COSE signatures and a real transcript agreed byte-for-byte between
 * the two halves.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import { buildOpenID4VPSessionTranscript } from '../src/mdoc/session-transcript.js'
import type { AgeClaims, CreatedRequest, Verifier, VerifierConfig } from '../src/types.js'
import { expectEudikitError } from './support.js'
import {
  AV_DOCTYPE,
  FIXED_NOW,
  type IssuerFixture,
  issueAttestation,
  makeIssuer,
  p256KeyPair,
  walletSignResponse,
} from './support-mdoc.js'

const PUBLIC_BASE = 'https://av-demo.example'
const RESPONSE_URI = `${PUBLIC_BASE}/api/eudikit/wallet/response`

const issuer: IssuerFixture = makeIssuer()
const device = p256KeyPair()

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

function makeVerifier(overrides: Partial<VerifierConfig> = {}): Verifier {
  return createVerifier({
    profile: 'av',
    publicBaseUrl: PUBLIC_BASE,
    session: memorySessionAdapter(),
    trust: { additionalTrustAnchors: [issuer.certificate] },
    now: () => FIXED_NOW,
    ...overrides,
  })
}

function deepLinkParams(created: CreatedRequest): URLSearchParams {
  if (created.channel !== 'deep-link') throw new Error('expected a deep-link request')
  return new URLSearchParams(created.deepLink.slice(created.deepLink.indexOf('?') + 1))
}

/** Rebuilds the transcript exactly as a spec-conforming wallet would: from the request URI. */
function walletTranscript(params: URLSearchParams, nonceOverride?: string): Uint8Array {
  return buildOpenID4VPSessionTranscript({
    clientId: params.get('client_id') ?? '',
    nonce: nonceOverride ?? params.get('nonce') ?? '',
    jwkThumbprint: null,
    responseUri: params.get('response_uri') ?? '',
  })
}

function formPost(body: string | URLSearchParams, contentType?: string): Request {
  return new Request(RESPONSE_URI, {
    method: 'POST',
    headers: { 'content-type': contentType ?? 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
}

interface WalletPostOptions {
  nonceOverride?: string
  claims?: Record<string, unknown>
  issuerOverride?: IssuerFixture
  validity?: { signed?: Date; validFrom?: Date; validUntil?: Date }
  iosFieldStyle?: boolean
  queryId?: string
}

/** Simulates the full wallet round trip for a created deep-link request. */
async function walletPost(
  created: CreatedRequest,
  options: WalletPostOptions = {}
): Promise<Request> {
  const params = deepLinkParams(created)
  const issuerSigned = await issueAttestation({
    issuer: options.issuerOverride ?? issuer,
    devicePublicJwk: device.publicJwk,
    ...(options.claims !== undefined ? { claims: options.claims } : {}),
    ...(options.validity !== undefined ? { validity: options.validity } : {}),
  })
  const presentation = await walletSignResponse({
    issuerSigned,
    devicePrivateJwk: device.privateJwk,
    sessionTranscript: walletTranscript(params, options.nonceOverride),
  })

  const queryId = options.queryId ?? 'av_proof_of_age'
  const form = new URLSearchParams()
  form.set('state', params.get('state') ?? '')
  if (options.iosFieldStyle === true) {
    form.set(`vp_token[${queryId}]`, presentation)
  } else {
    form.set('vp_token', JSON.stringify({ [queryId]: [presentation] }))
  }
  return formPost(form)
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>
}

// ---------------------------------------------------------------------------
// (a) happy path
// ---------------------------------------------------------------------------

describe('handleWalletResponse — happy path', () => {
  it('verifies a real wallet response end to end and exposes typed claims', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({
      preset: presets.age(),
      channel: 'deep-link',
    })

    const response = await verifier.handleWalletResponse(await walletPost(created))
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('application/json')
    expect(await json(response)).toEqual({})

    const status = await verifier.getResult<AgeClaims>(created.sessionId)
    if (status.status !== 'verified') {
      throw new Error(`expected verified, got ${status.status}: ${JSON.stringify(status)}`)
    }
    expect(status.result.verified).toBe(true)
    expect(status.result.policy).toBe('strict')
    expect(status.result.profile).toBe('av')
    expect(status.result.claims).toEqual({
      ageOver: true,
      threshold: 18,
      source: 'av-attestation',
    })
    expect(status.result.error).toBeNull()
    expect(status.result.sessionId).toBe(created.sessionId)

    const credential = status.result.credentials[0]
    expect(credential?.docType).toBe(AV_DOCTYPE)
    expect(credential?.claims.age_over_18).toBe(true)
    expect(credential?.issuer.subject).toContain('Test AV DS')
    expect(credential?.validity.validUntil.getTime()).toBeGreaterThan(FIXED_NOW.getTime())
  })

  it('reports the full diagnostics list on success, skipped checks included', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    await verifier.handleWalletResponse(await walletPost(created))

    const status = await verifier.getResult(created.sessionId)
    if (status.status !== 'verified') throw new Error('expected verified')
    const byId = new Map(status.result.diagnostics.map((check) => [check.id, check.status]))

    for (const id of [
      'session.found',
      'session.single_use',
      'session.state_match',
      'mdoc.decoded',
      'mdoc.response_status_ok',
      'mdoc.issuer_auth_present',
      'mdoc.issuer_chain_parsed',
      'mdoc.issuer_signature_valid',
      'mdoc.issuer_key_algorithm_allowed',
      'mdoc.doctype_consistent',
      'mdoc.value_digests_valid',
      'mdoc.device_signed_present',
      'mdoc.device_key_authorized',
      'mdoc.device_key_matches_mso',
      'mdoc.device_signature_valid',
      'trust.chain_valid',
      'trust.issuer_in_trusted_list',
      'dcql.doctype_match',
      'dcql.claims_present',
      'dcql.claim_types_valid',
      'dcql.credential_sets_satisfied',
    ] as const) {
      expect(byId.get(id), `check ${id}`).toBe('passed')
    }
    // Honestly reported gaps, not silent ones.
    expect(byId.get('mdoc.status_list_valid')).toBe('skipped')
    expect(byId.get('envelope.jwe_decrypted')).toBe('skipped')
    expect(byId.get('session.origin_allowed')).toBe('skipped')
  })

  it('accepts the iOS vp_token[queryId] form-field spelling', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const response = await verifier.handleWalletResponse(
      await walletPost(created, { iosFieldStyle: true })
    )
    expect(response.status).toBe(200)

    const status = await verifier.getResult<AgeClaims>(created.sessionId)
    expect(status.status).toBe('verified')
  })
})

// ---------------------------------------------------------------------------
// (g) replay + HTTP contract
// ---------------------------------------------------------------------------

describe('handleWalletResponse — replay and HTTP contract', () => {
  it('answers the second POST for the same state with an information-free 400', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const post = await walletPost(created)
    const body = await post.text()

    const first = await verifier.handleWalletResponse(formPost(body))
    expect(first.status).toBe(200)

    const replay = await verifier.handleWalletResponse(formPost(body))
    expect(replay.status).toBe(400)
    expect(await json(replay)).toEqual({ error: 'invalid_request' })

    // The first (real) result stays pollable; the replay changed nothing.
    const status = await verifier.getResult(created.sessionId)
    expect(status.status).toBe('verified')
  })

  it('rejects an unknown state with the same body as a replayed one', async () => {
    const verifier = makeVerifier()
    const unknown = await verifier.handleWalletResponse(
      formPost(new URLSearchParams({ state: 'never-issued', vp_token: '{}' }))
    )
    expect(unknown.status).toBe(400)
    expect(await json(unknown)).toEqual({ error: 'invalid_request' })
  })

  it('rejects a missing state, a wrong method and a wrong content type', async () => {
    const verifier = makeVerifier()

    const noState = await verifier.handleWalletResponse(
      formPost(new URLSearchParams({ vp_token: '{}' }))
    )
    expect(noState.status).toBe(400)

    const get = await verifier.handleWalletResponse(new Request(RESPONSE_URI, { method: 'GET' }))
    expect(get.status).toBe(405)
    expect(get.headers.get('allow')).toBe('POST')

    const wrongType = await verifier.handleWalletResponse(
      formPost(new URLSearchParams({ state: 'x' }), 'application/json')
    )
    expect(wrongType.status).toBe(400)
  })

  it('accepts a charset-suffixed form content type', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const body = await (await walletPost(created)).text()
    const response = await verifier.handleWalletResponse(
      formPost(body, 'application/x-www-form-urlencoded;charset=UTF-8')
    )
    expect(response.status).toBe(200)
  })

  it('refuses to complete a dc-api session through the direct_post endpoint', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({
      preset: presets.age(),
      channel: 'dc-api',
      profile: 'eudi',
    })
    const response = await verifier.handleWalletResponse(
      formPost(new URLSearchParams({ state: created.sessionId, vp_token: '{}' }))
    )
    expect(response.status).toBe(400)
    // The information-free body must hold here too: no session details, no key material.
    expect(await response.text()).toBe('{"error":"invalid_request"}')
  })
})

// ---------------------------------------------------------------------------
// (i) wallet error path
// ---------------------------------------------------------------------------

describe('handleWalletResponse — wallet error responses', () => {
  async function errorRoundTrip(walletError: string, description?: string) {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)
    const form = new URLSearchParams({ state: params.get('state') ?? '', error: walletError })
    if (description !== undefined) form.set('error_description', description)

    const response = await verifier.handleWalletResponse(formPost(form))
    expect(response.status).toBe(200)
    expect(await json(response)).toEqual({})

    const status = await verifier.getResult(created.sessionId)
    if (status.status !== 'failed') throw new Error(`expected failed, got ${status.status}`)
    return status.result
  }

  it('maps access_denied to the deliberately combined USER_DECLINED_OR_NO_CREDENTIAL', async () => {
    const result = await errorRoundTrip('access_denied')
    expect(result.verified).toBe(false)
    expect(result.error?.code).toBe('USER_DECLINED_OR_NO_CREDENTIAL')
    expect(result.error?.walletError).toBe('access_denied')
  })

  it('maps the invalid_* family to WALLET_REJECTED_REQUEST and preserves the raw code', async () => {
    for (const code of ['invalid_request', 'invalid_client', 'invalid_scope']) {
      const result = await errorRoundTrip(code, 'the request was malformed')
      expect(result.error?.code).toBe('WALLET_REJECTED_REQUEST')
      expect(result.error?.walletError).toBe(code)
      expect(result.error?.message).toContain('the request was malformed')
    }
  })

  it('maps vp_formats_not_supported to WALLET_FORMAT_UNSUPPORTED', async () => {
    const result = await errorRoundTrip('vp_formats_not_supported')
    expect(result.error?.code).toBe('WALLET_FORMAT_UNSUPPORTED')
  })
})

// ---------------------------------------------------------------------------
// (j) redirect mode + response_code
// ---------------------------------------------------------------------------

describe('handleWalletResponse — redirect mode', () => {
  const TEMPLATE = 'https://shop.example/age/done?code={RESPONSE_CODE}'

  it('returns a redirect_uri with a fresh ≥128-bit code and gates getResult on it', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({
      preset: presets.age(),
      channel: 'deep-link',
      successRedirectTemplate: TEMPLATE,
    })

    const response = await verifier.handleWalletResponse(await walletPost(created))
    expect(response.status).toBe(200)
    const body = await json(response)
    const redirectUri = body.redirect_uri as string
    expect(redirectUri.startsWith('https://shop.example/age/done?code=')).toBe(true)

    const code = new URL(redirectUri).searchParams.get('code') ?? ''
    // 32 random bytes → 43 base64url chars; ≥128 bits is 22.
    expect(code.length).toBeGreaterThanOrEqual(22)

    await expectEudikitError(() => verifier.getResult(created.sessionId), 'RESPONSE_CODE_MISMATCH')
    await expectEudikitError(
      () => verifier.getResult(created.sessionId, { responseCode: 'wrong' }),
      'RESPONSE_CODE_MISMATCH'
    )

    const status = await verifier.getResult<AgeClaims>(created.sessionId, { responseCode: code })
    expect(status.status).toBe('verified')
  })

  it('rejects a template without the {RESPONSE_CODE} placeholder at request creation', async () => {
    const verifier = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.requests.create({
          preset: presets.age(),
          channel: 'deep-link',
          successRedirectTemplate: 'https://shop.example/done',
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('{RESPONSE_CODE}')
  })
})

// ---------------------------------------------------------------------------
// malformed token + key-material hygiene
// ---------------------------------------------------------------------------

describe('handleWalletResponse — malformed responses and hygiene', () => {
  it('records a failed result when the POST carries neither vp_token nor error', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    const response = await verifier.handleWalletResponse(
      formPost(new URLSearchParams({ state: params.get('state') ?? '' }))
    )
    expect(response.status).toBe(200)

    const status = await verifier.getResult(created.sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(status.result.error?.code).toBe('PRESENTATION_MALFORMED')
  })

  it('records a failed result for an unparseable vp_token value', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    const response = await verifier.handleWalletResponse(
      formPost(new URLSearchParams({ state: params.get('state') ?? '', vp_token: 'not json' }))
    )
    expect(response.status).toBe(200)
    const status = await verifier.getResult(created.sessionId)
    expect(status.status).toBe('failed')
  })

  it('never leaks private key material into HTTP responses or stored diagnostics', async () => {
    // The dc-api record is the one holding an ephemeral private JWK; posting its session id to
    // the direct_post endpoint must produce the information-free 400, and the happy-path
    // result must not carry key material either.
    const session = memorySessionAdapter()
    const verifier = createVerifier({
      profile: 'av',
      publicBaseUrl: PUBLIC_BASE,
      session,
      trust: { additionalTrustAnchors: [issuer.certificate] },
      now: () => FIXED_NOW,
    })

    const dcApi = await verifier.requests.create({
      preset: presets.age(),
      channel: 'dc-api',
      profile: 'eudi',
    })
    const stored = await session.get(`request:${dcApi.sessionId}`)
    const privateD = (stored?.ephemeralPrivateJwk as { d?: string } | undefined)?.d
    expect(typeof privateD).toBe('string')

    const rejected = await verifier.handleWalletResponse(
      formPost(new URLSearchParams({ state: dcApi.sessionId, vp_token: '{}' }))
    )
    expect(await rejected.text()).not.toContain(privateD as string)

    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const ok = await verifier.handleWalletResponse(await walletPost(created))
    expect(await ok.text()).not.toContain(privateD as string)
    const status = await verifier.getResult(created.sessionId)
    expect(JSON.stringify(status)).not.toContain(privateD as string)
  })
})
