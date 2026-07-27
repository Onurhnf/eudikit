/**
 * The HTTP layer: `createFetchHandler` route table, surface control (name registry, channel
 * allowlists, no-registry-no-surface), the browser-facing result shaping with and without
 * diagnostics, the wallet-facing routes end to end, and `createNextHandler` /
 * `processWalletResponse` on top.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createFetchHandler, processWalletResponse } from '../src/handler/index.js'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import {
  buildOpenID4VPDCAPISessionTranscript,
  buildOpenID4VPSessionTranscript,
} from '../src/mdoc/session-transcript.js'
import { createNextHandler } from '../src/next/index.js'
import type { Verifier, VerifierConfig } from '../src/types.js'
import { encryptWalletResponse } from './support-jwe.js'
import {
  FIXED_NOW,
  type IssuerFixture,
  issueAttestation,
  makeIssuer,
  p256KeyPair,
  selfSignedCertificate,
  walletSignResponse,
} from './support-mdoc.js'

const PUBLIC_BASE = 'https://av-demo.example'
const BASE = '/api/eudikit'

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
    trust: { additionalTrustAnchors: [issuer.certificate], avTrustedList: false },
    now: () => FIXED_NOW,
    ...overrides,
  })
}

type Handler = (request: Request) => Promise<Response>

function makeHandler(
  overrides: Partial<VerifierConfig> = {},
  options?: Parameters<typeof createFetchHandler>[1]
): { verifier: Verifier; handler: Handler } {
  const verifier = makeVerifier(overrides)
  return {
    verifier,
    handler: createFetchHandler(
      verifier,
      options ?? { requests: { age: { preset: presets.age(), channels: ['qr', 'deep-link'] } } }
    ),
  }
}

function jsonPost(path: string, body: unknown): Request {
  return new Request(`${PUBLIC_BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function get(path: string): Request {
  return new Request(`${PUBLIC_BASE}${path}`)
}

async function body(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>
}

/** The wallet round trip against whatever deep link `POST /requests` returned. */
async function walletForm(created: Record<string, unknown>): Promise<URLSearchParams> {
  const deepLink = created.deepLink as string
  const params = new URLSearchParams(deepLink.slice(deepLink.indexOf('?') + 1))
  const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
  const presentation = await walletSignResponse({
    issuerSigned,
    devicePrivateJwk: device.privateJwk,
    sessionTranscript: buildOpenID4VPSessionTranscript({
      clientId: params.get('client_id') as string,
      nonce: params.get('nonce') as string,
      jwkThumbprint: null,
      responseUri: params.get('response_uri') as string,
    }),
  })
  const form = new URLSearchParams()
  form.set('state', params.get('state') as string)
  form.set('vp_token', JSON.stringify({ av_proof_of_age: [presentation] }))
  return form
}

function formPost(path: string, form: URLSearchParams): Request {
  return new Request(`${PUBLIC_BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  })
}

// ---------------------------------------------------------------------------
// POST {base}/requests — surface control
// ---------------------------------------------------------------------------

describe('handler — POST /requests', () => {
  it('builds a registered request and serializes CreatedRequest with an ISO expiresAt', async () => {
    const { handler } = makeHandler()
    const response = await handler(
      jsonPost(`${BASE}/requests`, { name: 'age', channel: 'deep-link' })
    )
    expect(response.status).toBe(200)
    const created = await body(response)
    expect(created.channel).toBe('deep-link')
    expect(typeof created.sessionId).toBe('string')
    expect(created.deepLink).toContain('://authorize?')
    expect(created.expiresAt).toBe(new Date(FIXED_NOW.getTime() + 900_000).toISOString())
  })

  it('404s unknown names without listing what exists', async () => {
    const { handler } = makeHandler()
    const response = await handler(
      jsonPost(`${BASE}/requests`, { name: 'identity', channel: 'qr' })
    )
    expect(response.status).toBe(404)
    expect(await body(response)).toEqual({ error: 'unknown_request' })
  })

  it('enforces the per-name channel allowlist', async () => {
    const { handler } = makeHandler()
    const response = await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'dc-api' }))
    expect(response.status).toBe(400)
    expect(await body(response)).toEqual({ error: 'channel_not_allowed' })
  })

  it('exposes no request surface at all without a registry', async () => {
    const { handler } = makeHandler({}, {})
    const response = await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'qr' }))
    expect(response.status).toBe(404)
    expect(await body(response)).toEqual({ error: 'not_found' })
  })

  it('maps config-class EudikitErrors to 400 with the bare code', async () => {
    // profile 'av' + channel 'dc-api' is the wallet-trap guard; a client can trigger it, so
    // it must surface as a client error, not a 500.
    const { handler } = makeHandler({}, { requests: { age: { preset: presets.age() } } })
    const response = await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'dc-api' }))
    expect(response.status).toBe(400)
    expect(await body(response)).toEqual({ error: 'CHANNEL_PROFILE_MISMATCH' })
  })

  it('rejects malformed bodies with 400', async () => {
    const { handler } = makeHandler()
    for (const junk of ['not json', JSON.stringify(['array']), JSON.stringify({ name: 7 })]) {
      const response = await handler(
        new Request(`${PUBLIC_BASE}${BASE}/requests`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: junk,
        })
      )
      expect(response.status).toBe(400)
    }
  })
})

// ---------------------------------------------------------------------------
// routing table, methods, base path
// ---------------------------------------------------------------------------

describe('handler — routing and method guards', () => {
  it('enforces the method per route with an Allow header', async () => {
    const { handler } = makeHandler()
    const cases: Array<[Request, string]> = [
      [get(`${BASE}/requests`), 'POST'],
      [get(`${BASE}/verify`), 'POST'],
      [get(`${BASE}/wallet/response`), 'POST'],
      [new Request(`${PUBLIC_BASE}${BASE}/sessions/abc`, { method: 'POST' }), 'GET'],
      [new Request(`${PUBLIC_BASE}${BASE}/wallet/request/abc.jwt`, { method: 'POST' }), 'GET'],
    ]
    for (const [request, allow] of cases) {
      const response = await handler(request)
      expect(response.status, request.url).toBe(405)
      expect(response.headers.get('allow')).toBe(allow)
    }
  })

  it('404s outside the route base path and for unknown routes inside it', async () => {
    const { handler } = makeHandler()
    for (const path of ['/other/requests', `${BASE}/nope`, `${BASE}/sessions/a/b`, '/requests']) {
      const response = await handler(jsonPost(path, {}))
      expect(response.status, path).toBe(404)
    }
  })

  it('respects a custom routeBasePath', async () => {
    const { handler } = makeHandler({ routeBasePath: '/hooks/wallet' })
    const miss = await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'qr' }))
    expect(miss.status).toBe(404)
    const hit = await handler(jsonPost('/hooks/wallet/requests', { name: 'age', channel: 'qr' }))
    expect(hit.status).toBe(200)
  })

  it('refuses a hand-rolled verifier object', () => {
    expect(() => createFetchHandler({} as unknown as Verifier)).toThrowError(/createVerifier/)
  })
})

// ---------------------------------------------------------------------------
// wallet routes + poll, end to end
// ---------------------------------------------------------------------------

describe('handler — direct_post flow end to end', () => {
  it('serves /requests → /wallet/response → /sessions/{id} with browser-safe bodies', async () => {
    const { handler } = makeHandler()
    const created = await body(
      await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'deep-link' }))
    )

    const pending = await body(
      await handler(get(`${BASE}/sessions/${created.sessionId as string}`))
    )
    expect(pending).toEqual({ status: 'pending' })

    const post = await handler(formPost(`${BASE}/wallet/response`, await walletForm(created)))
    expect(post.status).toBe(200)
    expect(await body(post)).toEqual({})

    const verified = await body(
      await handler(get(`${BASE}/sessions/${created.sessionId as string}`))
    )
    expect(verified).toEqual({
      status: 'verified',
      verified: true,
      claims: { ageOver: true, threshold: 18, source: 'av-attestation' },
    })
    // Diagnostics stay server-side unless opted into.
    expect(verified.diagnostics).toBeUndefined()
  })

  it('adds diagnostics to poll bodies only with exposeDiagnostics: true', async () => {
    const { verifier } = makeHandler()
    const handler = createFetchHandler(verifier, {
      requests: { age: { preset: presets.age() } },
      exposeDiagnostics: true,
    })
    const created = await body(
      await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'deep-link' }))
    )
    await handler(formPost(`${BASE}/wallet/response`, await walletForm(created)))

    const polled = await body(await handler(get(`${BASE}/sessions/${created.sessionId as string}`)))
    expect(polled.status).toBe('verified')
    expect(Array.isArray(polled.diagnostics)).toBe(true)
  })

  it('reports failed outcomes with the stable error shape', async () => {
    const { handler } = makeHandler()
    const created = await body(
      await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'deep-link' }))
    )
    const deepLink = created.deepLink as string
    const params = new URLSearchParams(deepLink.slice(deepLink.indexOf('?') + 1))
    const form = new URLSearchParams()
    form.set('state', params.get('state') as string)
    form.set('error', 'access_denied')
    await handler(formPost(`${BASE}/wallet/response`, form))

    const polled = await body(await handler(get(`${BASE}/sessions/${created.sessionId as string}`)))
    expect(polled.status).toBe('failed')
    expect(polled.verified).toBe(false)
    expect(polled.error).toEqual({
      code: 'USER_DECLINED_OR_NO_CREDENTIAL',
      message: 'the wallet returned "access_denied"',
      walletError: 'access_denied',
    })
  })

  it('guards redirect-mode results behind the response_code', async () => {
    const { handler } = makeHandler(
      {},
      {
        requests: {
          age: {
            preset: presets.age(),
            successRedirectTemplate: 'https://shop.example/done?code={RESPONSE_CODE}',
          },
        },
      }
    )
    const created = await body(
      await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'deep-link' }))
    )
    const post = await body(
      await handler(formPost(`${BASE}/wallet/response`, await walletForm(created)))
    )
    const redirectUri = new URL(post.redirect_uri as string)
    const code = redirectUri.searchParams.get('code') as string

    const noCode = await handler(get(`${BASE}/sessions/${created.sessionId as string}`))
    expect(noCode.status).toBe(403)
    expect(await body(noCode)).toEqual({ error: 'RESPONSE_CODE_MISMATCH' })

    const withCode = await body(
      await handler(get(`${BASE}/sessions/${created.sessionId as string}?response_code=${code}`))
    )
    expect(withCode.status).toBe('verified')
  })

  it('answers /sessions for unknown ids with the expired shape', async () => {
    const { handler } = makeHandler()
    expect(await body(await handler(get(`${BASE}/sessions/never-issued`)))).toEqual({
      status: 'expired',
    })
  })
})

describe('handler — DC API flow through /verify', () => {
  it('verifies an encrypted dc_api.jwt response posted by the app backend-to-backend', async () => {
    const origin = 'https://shop.example'
    const { handler } = makeHandler(
      { profile: 'eudi', expectedOrigins: [origin] },
      { requests: { age: { preset: presets.age(), channels: ['dc-api'] } } }
    )
    const created = await body(
      await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'dc-api' }))
    )
    const dcApiRequest = created.dcApiRequest as {
      protocol: string
      data: { nonce: string; client_metadata: { jwks: { keys: [Record<string, unknown>] } } }
    }
    expect(dcApiRequest.protocol).toBe('openid4vp-v1-unsigned')
    const encryptionJwk = dcApiRequest.data.client_metadata.jwks.keys[0]

    const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: buildOpenID4VPDCAPISessionTranscript({
        origin,
        nonce: dcApiRequest.data.nonce,
        jwkThumbprint: Uint8Array.from(Buffer.from(encryptionJwk.kid as string, 'base64url')),
      }),
    })
    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [presentation] } },
      recipientJwk: encryptionJwk,
      apv: dcApiRequest.data.nonce,
    })

    const verified = await body(
      await handler(
        jsonPost(`${BASE}/verify`, {
          sessionId: created.sessionId,
          response: { protocol: 'openid4vp-v1-unsigned', data: { response: jwe } },
        })
      )
    )
    expect(verified.status).toBe('verified')
    expect(verified.claims).toEqual({ ageOver: true, threshold: 18, source: 'av-attestation' })

    // Replay across HTTP maps to 409.
    const replay = await handler(
      jsonPost(`${BASE}/verify`, {
        sessionId: created.sessionId,
        response: { protocol: 'openid4vp-v1-unsigned', data: { response: jwe } },
      })
    )
    expect(replay.status).toBe(409)
    expect(await body(replay)).toEqual({ error: 'SESSION_ALREADY_CONSUMED' })
  })

  it('maps unknown sessions to 404 and unsupported protocols to 400', async () => {
    const { handler } = makeHandler({ profile: 'eudi', expectedOrigins: ['https://x.example'] })
    const notFound = await handler(
      jsonPost(`${BASE}/verify`, {
        sessionId: 'ghost',
        response: { protocol: 'openid4vp-v1-unsigned', data: {} },
      })
    )
    expect(notFound.status).toBe(404)
    expect(await body(notFound)).toEqual({ error: 'SESSION_NOT_FOUND' })

    const wrongProtocol = await handler(
      jsonPost(`${BASE}/verify`, {
        sessionId: 'ghost',
        response: { protocol: 'org-iso-mdoc', data: {} },
      })
    )
    expect(wrongProtocol.status).toBe(400)
    expect(await body(wrongProtocol)).toEqual({ error: 'UNSUPPORTED_PROTOCOL' })
  })
})

// ---------------------------------------------------------------------------
// request_uri route + secrets hygiene + adapters
// ---------------------------------------------------------------------------

describe('handler — request_uri route and secrets hygiene', () => {
  it('serves the JAR through the routed path exactly once', async () => {
    const signer = p256KeyPair()
    const cert = selfSignedCertificate(signer, { commonName: 'hash-client' })
    const { handler } = makeHandler(
      {
        profile: 'eudi',
        clientIdPrefix: 'x509_hash',
        keys: {
          requestSigning: {
            pem: signer.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
          },
          requestSigningCertificateChain: [
            `-----BEGIN CERTIFICATE-----\n${Buffer.from(cert).toString('base64')}\n-----END CERTIFICATE-----`,
          ],
        },
      },
      { requests: { age: { preset: presets.age() } } }
    )
    const created = await body(
      await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'qr' }))
    )
    const requestUri = created.requestUri as string
    expect(requestUri).toContain(`${BASE}/wallet/request/`)

    const first = await handler(get(new URL(requestUri).pathname))
    expect(first.status).toBe(200)
    expect(first.headers.get('content-type')).toBe('application/oauth-authz-req+jwt')
    expect((await first.text()).split('.')).toHaveLength(3)

    const second = await handler(get(new URL(requestUri).pathname))
    expect(second.status).toBe(404)
  })

  it('never leaks private key material through any handler response', async () => {
    const { handler } = makeHandler(
      { profile: 'eudi', expectedOrigins: ['https://shop.example'] },
      { requests: { age: { preset: presets.age() } }, exposeDiagnostics: true }
    )
    const createdResponse = await handler(
      jsonPost(`${BASE}/requests`, { name: 'age', channel: 'dc-api' })
    )
    const createdText = await createdResponse.text()
    // The ephemeral pair's private scalar lives in the session record only; the public JWK
    // in client_metadata has x/y and no "d".
    expect(createdText).toContain('"client_metadata"')
    expect(createdText).not.toContain('"d"')

    const created = JSON.parse(createdText) as { sessionId: string }
    const polled = await handler(get(`${BASE}/sessions/${created.sessionId}`))
    expect(await polled.text()).not.toContain('"d"')
  })
})

describe('handler — adapters', () => {
  it('processWalletResponse mirrors handleWalletResponse for form frameworks', async () => {
    const { verifier, handler } = makeHandler()
    const created = await body(
      await handler(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'deep-link' }))
    )
    const { status, body: responseBody } = await processWalletResponse(
      verifier,
      await walletForm(created)
    )
    expect(status).toBe(200)
    expect(responseBody).toEqual({})
    const polled = await body(await handler(get(`${BASE}/sessions/${created.sessionId as string}`)))
    expect(polled.status).toBe('verified')
  })

  it('createNextHandler exposes the same handler as GET and POST', async () => {
    const verifier = makeVerifier()
    const { GET, POST } = createNextHandler(verifier, {
      requests: { age: { preset: presets.age() } },
    })
    const created = await body(
      await POST(jsonPost(`${BASE}/requests`, { name: 'age', channel: 'deep-link' }))
    )
    expect(typeof created.sessionId).toBe('string')
    const polled = await body(await GET(get(`${BASE}/sessions/${created.sessionId as string}`)))
    expect(polled).toEqual({ status: 'pending' })
  })
})
