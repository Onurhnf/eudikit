/**
 * Signed Request Objects (JAR) and their transports: the JWS itself (typ, alg, x5c, claims),
 * the by-reference `request_uri` endpoint with its serve-once contract, the by-value
 * `request` parameter, the signed DC API shape with `expected_origins` — and the full
 * `'eudi'` QR flow end to end: fetch the JAR like a wallet, answer encrypted like a wallet,
 * poll the verified result.
 */

import { generateKeyPairSync, X509Certificate } from 'node:crypto'
import { calculateJwkThumbprint, decodeProtectedHeader, jwtVerify } from 'jose'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import { buildOpenID4VPSessionTranscript } from '../src/mdoc/session-transcript.js'
import type { Verifier, VerifierConfig } from '../src/types.js'
import { expectEudikitError } from './support.js'
import { encryptWalletResponse } from './support-jwe.js'
import {
  ecKeyPair,
  FIXED_NOW,
  type IssuerFixture,
  issueAttestation,
  makeIssuer,
  p256KeyPair,
  selfSignedCertificate,
  type TestKeyPair,
  walletSignResponse,
} from './support-mdoc.js'

const PUBLIC_BASE = 'https://verifier.example'
const DNS_NAME = 'verifier.example'

const signer: TestKeyPair = p256KeyPair()
const signerCert = selfSignedCertificate(signer, { commonName: DNS_NAME, san: [DNS_NAME] })
const signerCertPem = derToPem(signerCert)
const signerPkcs8 = signer.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string

const issuer: IssuerFixture = makeIssuer()
const device = p256KeyPair()

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

function derToPem(der: Uint8Array): string {
  const b64 = Buffer.from(der)
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`
}

function makeSignedVerifier(overrides: Partial<VerifierConfig> = {}): Verifier {
  return createVerifier({
    profile: 'eudi',
    publicBaseUrl: PUBLIC_BASE,
    clientId: DNS_NAME,
    clientIdPrefix: 'x509_san_dns',
    keys: {
      requestSigning: { pem: signerPkcs8 },
      requestSigningCertificateChain: [signerCertPem],
    },
    session: memorySessionAdapter(),
    trust: { additionalTrustAnchors: [issuer.certificate], avTrustedList: false },
    now: () => FIXED_NOW,
    ...overrides,
  })
}

/** Signing keys configured, but no explicit clientIdPrefix/clientId — the profile default applies. */
function makeNoPrefixVerifier(): Verifier {
  return createVerifier({
    profile: 'eudi',
    publicBaseUrl: PUBLIC_BASE,
    keys: {
      requestSigning: { pem: signerPkcs8 },
      requestSigningCertificateChain: [signerCertPem],
    },
    session: memorySessionAdapter(),
    trust: { additionalTrustAnchors: [issuer.certificate], avTrustedList: false },
    now: () => FIXED_NOW,
  })
}

function uriParams(uri: string): URLSearchParams {
  return new URLSearchParams(uri.slice(uri.indexOf('?') + 1))
}

async function fetchJar(verifier: Verifier, requestUri: string, sessionId: string) {
  return verifier.handleRequestUri(new Request(requestUri), sessionId)
}

// ---------------------------------------------------------------------------
// the Request Object itself
// ---------------------------------------------------------------------------

describe('signed request objects — JWS shape and claims', () => {
  it("defaults 'eudi' QR to signed by-reference and serves a spec-shaped JAR once", async () => {
    const verifier = makeSignedVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')

    // The QR URI is short: exactly client_id + request_uri.
    const params = uriParams(created.qrPayload)
    expect([...params.keys()].sort()).toEqual(['client_id', 'request_uri'])
    expect(params.get('client_id')).toBe(`x509_san_dns:${DNS_NAME}`)
    expect(params.get('request_uri')).toBe(created.requestUri)
    expect(created.requestUri).toBe(
      `${PUBLIC_BASE}/api/eudikit/wallet/request/${created.sessionId}.jwt`
    )

    const response = await fetchJar(verifier, created.requestUri as string, created.sessionId)
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toBe('application/oauth-authz-req+jwt')
    const jar = await response.text()

    const header = decodeProtectedHeader(jar)
    expect(header.typ).toBe('oauth-authz-req+jwt')
    expect(header.alg).toBe('ES256')
    expect(header.x5c).toEqual([Buffer.from(signerCert).toString('base64')])

    // Signature verifies against the certificate the header carries; aud/iat/exp are pinned.
    const certificate = new X509Certificate(Buffer.from(signerCert))
    const { payload } = await jwtVerify(jar, certificate.publicKey, {
      audience: 'https://self-issued.me/v2',
      typ: 'oauth-authz-req+jwt',
      currentDate: FIXED_NOW,
    })
    expect(payload.client_id).toBe(`x509_san_dns:${DNS_NAME}`)
    expect(payload.response_type).toBe('vp_token')
    expect(payload.response_mode).toBe('direct_post.jwt')
    expect(payload.response_uri).toBe(`${PUBLIC_BASE}/api/eudikit/wallet/response`)
    expect(payload.state).toBe(created.sessionId)
    expect(typeof payload.nonce).toBe('string')
    expect(payload.dcql_query).toEqual(presets.age().dcql)
    expect(payload.iat).toBe(Math.floor(FIXED_NOW.getTime() / 1000))
    expect(payload.exp).toBe(Math.floor(FIXED_NOW.getTime() / 1000) + 900)
    const metadata = payload.client_metadata as {
      jwks: { keys: Array<Record<string, unknown>> }
      encrypted_response_enc_values_supported: string[]
    }
    expect(metadata.encrypted_response_enc_values_supported).toEqual(['A128GCM'])
    expect(metadata.jwks.keys[0]?.kty).toBe('EC')
    expect(metadata.jwks.keys[0]?.d).toBeUndefined()
  })

  it('serves the JAR exactly once: the second GET is an information-free 404', async () => {
    const verifier = makeSignedVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')

    const first = await fetchJar(verifier, created.requestUri as string, created.sessionId)
    expect(first.status).toBe(200)

    const second = await fetchJar(verifier, created.requestUri as string, created.sessionId)
    expect(second.status).toBe(404)
    expect(await second.text()).toBe('')

    // The session itself survives the serve — polling still says pending.
    expect((await verifier.getResult(created.sessionId)).status).toBe('pending')
  })

  it('rejects non-GET methods on the request_uri endpoint', async () => {
    const verifier = makeSignedVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')
    const response = await verifier.handleRequestUri(
      new Request(created.requestUri as string, { method: 'POST' }),
      created.sessionId
    )
    expect(response.status).toBe(405)
    expect(response.headers.get('allow')).toBe('GET')
  })

  it("inlines the JWS as a `request` parameter for jarMode 'by-value'", async () => {
    const verifier = makeSignedVerifier()
    const created = await verifier.requests.create({
      preset: presets.age(),
      channel: 'deep-link',
      jarMode: 'by-value',
    })
    if (created.channel !== 'deep-link') throw new Error('expected deep-link')
    expect(created.requestUri).toBeUndefined()
    const params = uriParams(created.deepLink)
    expect([...params.keys()].sort()).toEqual(['client_id', 'request'])
    const header = decodeProtectedHeader(params.get('request') as string)
    expect(header.typ).toBe('oauth-authz-req+jwt')
  })

  it('derives the x509_hash client id from the leaf certificate', async () => {
    const verifier = createVerifier({
      profile: 'eudi',
      publicBaseUrl: PUBLIC_BASE,
      clientIdPrefix: 'x509_hash',
      keys: {
        requestSigning: { pem: signerPkcs8 },
        requestSigningCertificateChain: [signerCertPem],
      },
      session: memorySessionAdapter(),
      trust: { additionalTrustAnchors: [issuer.certificate], avTrustedList: false },
      now: () => FIXED_NOW,
    })
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')
    const expected = `x509_hash:${Buffer.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.from(signerCert)))
    ).toString('base64url')}`
    expect(uriParams(created.qrPayload).get('client_id')).toBe(expected)
  })

  it("defaults profile 'eudi' to the x509_hash prefix when none is configured", async () => {
    const verifier = makeNoPrefixVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')
    const expected = `x509_hash:${Buffer.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.from(signerCert)))
    ).toString('base64url')}`
    expect(uriParams(created.qrPayload).get('client_id')).toBe(expected)
  })

  it("a per-request profile 'av' override falls back to the unsigned redirect_uri flow", async () => {
    // The prefix default follows the effective profile of the request, so an 'eudi' verifier
    // with signing keys can still mint plain AV requests without per-request prefix juggling.
    const verifier = makeNoPrefixVerifier()
    const created = await verifier.requests.create({
      preset: presets.age(),
      channel: 'deep-link',
      profile: 'av',
    })
    if (created.channel !== 'deep-link') throw new Error('expected deep-link')
    expect(created.requestUri).toBeUndefined()
    const params = uriParams(created.deepLink)
    expect(params.get('client_id')).toBe(`redirect_uri:${PUBLIC_BASE}/api/eudikit/wallet/response`)
    expect(params.get('response_mode')).toBe('direct_post')
  })

  it('never advertises request_uri_method — absent means GET, the only method the endpoint serves', async () => {
    const verifier = makeSignedVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')
    expect(uriParams(created.qrPayload).get('request_uri_method')).toBeNull()
  })

  it('signs with the algorithm the key curve requires (P-384 → ES384)', async () => {
    const signer384 = ecKeyPair('P-384')
    const cert384 = selfSignedCertificate(signer384, { commonName: DNS_NAME, san: [DNS_NAME] })
    const verifier = makeSignedVerifier({
      keys: {
        requestSigning: {
          pem: signer384.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
        },
        requestSigningCertificateChain: [derToPem(cert384)],
      },
    })
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')
    const response = await fetchJar(verifier, created.requestUri as string, created.sessionId)
    expect(decodeProtectedHeader(await response.text()).alg).toBe('ES384')
  })

  it('emits the signed DC API shape with the mandatory expected_origins claim', async () => {
    const verifier = makeSignedVerifier({ expectedOrigins: ['https://shop.example'] })
    const created = await verifier.requests.create({
      preset: presets.age(),
      channel: 'dc-api',
      signedRequest: true,
    })
    if (created.channel !== 'dc-api') throw new Error('expected dc-api')
    expect(created.dcApiRequest.protocol).toBe('openid4vp-v1-signed')
    const jws = created.dcApiRequest.data.request as string
    const certificate = new X509Certificate(Buffer.from(signerCert))
    const { payload } = await jwtVerify(jws, certificate.publicKey, {
      typ: 'oauth-authz-req+jwt',
      currentDate: FIXED_NOW,
    })
    expect(payload.client_id).toBe(`x509_san_dns:${DNS_NAME}`)
    expect(payload.expected_origins).toEqual(['https://shop.example'])
    expect(payload.response_mode).toBe('dc_api.jwt')
    expect(payload.state).toBeUndefined()
    expect(payload.response_uri).toBeUndefined()
  })

  it('refuses a signed DC API request without expected origins', async () => {
    const verifier = makeSignedVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.requests.create({ preset: presets.age(), channel: 'dc-api', signedRequest: true }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('expected_origins')
  })
})

// ---------------------------------------------------------------------------
// key/certificate configuration errors
// ---------------------------------------------------------------------------

describe('signed request objects — configuration validation', () => {
  it('rejects a clientId that is not a dNSName SAN of the leaf', () => {
    expect(() => makeSignedVerifier({ clientId: 'wrong.example' })).not.toThrow()
    // The mismatch surfaces at request creation, where the prefix is known.
    const verifier = makeSignedVerifier({ clientId: 'wrong.example' })
    return expectEudikitError(
      () => verifier.requests.create({ preset: presets.age(), channel: 'qr' }),
      'CONFIG_INVALID'
    ).then((error) => {
      expect(error.message).toContain('wrong.example')
      expect(error.message).toContain(DNS_NAME)
    })
  })

  it('rejects a signing key that does not match the leaf certificate at boot', () => {
    const otherKey = p256KeyPair()
    expect(() =>
      makeSignedVerifier({
        keys: {
          requestSigning: {
            pem: otherKey.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
          },
          requestSigningCertificateChain: [signerCertPem],
        },
      })
    ).toThrowError(/does not match the public key/)
  })

  it('rejects a declared alg that contradicts the key curve', () => {
    expect(() =>
      makeSignedVerifier({
        keys: {
          requestSigning: { pem: signerPkcs8, alg: 'ES384' },
          requestSigningCertificateChain: [signerCertPem],
        },
      })
    ).toThrowError(/ES256/)
  })

  it('rejects non-EC keys', () => {
    const { privateKey } = generateKeyPairSync('ed25519')
    expect(() =>
      makeSignedVerifier({
        keys: {
          requestSigning: {
            jwk: privateKey.export({ format: 'jwk' }) as unknown as { kty: string },
          },
          requestSigningCertificateChain: [signerCertPem],
        },
      })
    ).toThrowError(/EC P-256/)
  })

  it('requires the certificate chain for x509 prefixes even when a key exists', async () => {
    const verifier = makeSignedVerifier({
      keys: { requestSigning: { pem: signerPkcs8 } },
    })
    const error = await expectEudikitError(
      () => verifier.requests.create({ preset: presets.age(), channel: 'qr' }),
      'CONFIG_SIGNING_KEY_REQUIRED'
    )
    expect(error.message).toContain('requestSigningCertificateChain')
  })

  it('falls back to the EUDIKIT_SIGNING_KEY env var', async () => {
    vi.stubEnv('EUDIKIT_SIGNING_KEY', signerPkcs8)
    try {
      const verifier = makeSignedVerifier({
        keys: { requestSigningCertificateChain: [signerCertPem] },
      })
      const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
      expect(created.channel).toBe('qr')
    } finally {
      vi.unstubAllEnvs()
    }
  })
})

// ---------------------------------------------------------------------------
// the whole 'eudi' QR flow, wallet-side simulated from the JAR alone
// ---------------------------------------------------------------------------

describe('signed by-reference + direct_post.jwt — end to end', () => {
  it('verifies a wallet that fetched the JAR and answered encrypted', async () => {
    const verifier = makeSignedVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'qr' })
    if (created.channel !== 'qr') throw new Error('expected qr')

    // Wallet side, driven exclusively by what the wallet can see: the QR params + the JAR.
    const jarResponse = await fetchJar(verifier, created.requestUri as string, created.sessionId)
    const jar = await jarResponse.text()
    const certificate = new X509Certificate(Buffer.from(signerCert))
    const { payload } = await jwtVerify(jar, certificate.publicKey, {
      typ: 'oauth-authz-req+jwt',
      currentDate: FIXED_NOW,
    })
    const metadata = payload.client_metadata as { jwks: { keys: [Record<string, unknown>] } }
    const encryptionJwk = metadata.jwks.keys[0]

    const thumbprint = Uint8Array.from(
      Buffer.from(
        await calculateJwkThumbprint(encryptionJwk as Parameters<typeof calculateJwkThumbprint>[0]),
        'base64url'
      )
    )
    const issuerSigned = await issueAttestation({
      issuer,
      devicePublicJwk: device.publicJwk,
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: buildOpenID4VPSessionTranscript({
        clientId: payload.client_id as string,
        nonce: payload.nonce as string,
        jwkThumbprint: thumbprint,
        responseUri: payload.response_uri as string,
      }),
    })

    const jwe = await encryptWalletResponse({
      payload: {
        vp_token: { av_proof_of_age: [presentation] },
        state: payload.state,
      },
      recipientJwk: encryptionJwk,
      apv: payload.nonce as string,
    })

    const post = await verifier.handleWalletResponse(
      new Request(payload.response_uri as string, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ response: jwe }).toString(),
      })
    )
    expect(post.status).toBe(200)
    expect(await post.json()).toEqual({})

    const status = await verifier.getResult(created.sessionId)
    if (status.status !== 'verified') {
      throw new Error(`expected verified: ${JSON.stringify(status)}`)
    }
    expect(status.result.claims).toEqual({ ageOver: true, threshold: 18, source: 'av-attestation' })
    const byId = new Map(status.result.diagnostics.map((check) => [check.id, check.status]))
    expect(byId.get('envelope.jwe_decrypted')).toBe('passed')
    expect(byId.get('envelope.key_binding')).toBe('passed')
    expect(byId.get('session.state_match')).toBe('passed')
    expect(byId.get('mdoc.device_signature_valid')).toBe('passed')
  })
})
