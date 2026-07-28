/**
 * `direct_post.jwt` — the encrypted response path of the QR/deep-link channel, driven through
 * `handleWalletResponse` with real JWEs: the full round trip, every documented failure mode
 * (wrong key, unroutable kid, apv mismatch, cleartext downgrade, replay), and the §14.5
 * re-encryption defense — a transcript without the ephemeral-key thumbprint must not verify.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import { buildOpenID4VPSessionTranscript } from '../src/mdoc/session-transcript.js'
import type { Check, CreatedRequest, Verifier, VerifierConfig } from '../src/types.js'
import { JWE_KID_KEY_PREFIX, REQUEST_KEY_PREFIX } from '../src/verifier/create-request.js'
import { encryptWalletResponse } from './support-jwe.js'
import {
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
    profile: 'eudi',
    publicBaseUrl: PUBLIC_BASE,
    session: memorySessionAdapter(),
    trust: { additionalTrustAnchors: [issuer.certificate], avTrustedList: false },
    now: () => FIXED_NOW,
    ...overrides,
  })
}

interface EncryptedFlow {
  verifier: Verifier
  created: CreatedRequest & { channel: 'deep-link' }
  params: URLSearchParams
  encryptionJwk: Record<string, unknown>
  nonce: string
  state: string
}

/** Creates the unsigned-but-encrypted 'eudi' deep-link request and unpacks what a wallet sees. */
async function startFlow(verifier = makeVerifier()): Promise<EncryptedFlow> {
  const created = await verifier.requests.create({
    preset: presets.age(),
    channel: 'deep-link',
    signedRequest: false,
  })
  if (created.channel !== 'deep-link') throw new Error('expected deep-link')
  const params = new URLSearchParams(created.deepLink.slice(created.deepLink.indexOf('?') + 1))
  expect(params.get('response_mode')).toBe('direct_post.jwt')
  const metadata = JSON.parse(params.get('client_metadata') ?? '{}') as {
    jwks: { keys: [Record<string, unknown>] }
  }
  return {
    verifier,
    created,
    params,
    encryptionJwk: metadata.jwks.keys[0],
    nonce: params.get('nonce') as string,
    state: params.get('state') as string,
  }
}

/** The wallet's DeviceResponse over the thumbprint-bearing transcript. */
async function signPresentation(
  flow: EncryptedFlow,
  options: { thumbprint?: Uint8Array | null } = {}
): Promise<string> {
  const thumbprint =
    options.thumbprint !== undefined
      ? options.thumbprint
      : Uint8Array.from(Buffer.from(flow.encryptionJwk.kid as string, 'base64url'))
  const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
  return walletSignResponse({
    issuerSigned,
    devicePrivateJwk: device.privateJwk,
    sessionTranscript: buildOpenID4VPSessionTranscript({
      clientId: flow.params.get('client_id') as string,
      nonce: flow.nonce,
      jwkThumbprint: thumbprint,
      responseUri: flow.params.get('response_uri') as string,
    }),
  })
}

function post(verifier: Verifier, body: URLSearchParams): Promise<Response> {
  return verifier.handleWalletResponse(
    new Request(RESPONSE_URI, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
  )
}

function checkStatus(checks: Check[], id: Check['id']): Check['status'] | undefined {
  return checks.find((check) => check.id === id)?.status
}

describe('direct_post.jwt — round trip', () => {
  it('decrypts, binds and verifies a spec-conforming encrypted response', async () => {
    const flow = await startFlow()
    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signPresentation(flow)] }, state: flow.state },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })

    const response = await post(flow.verifier, new URLSearchParams({ response: jwe }))
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({})

    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'verified') {
      throw new Error(`expected verified: ${JSON.stringify(status)}`)
    }
    const d = status.result.diagnostics
    expect(checkStatus(d, 'envelope.jwe_decrypted')).toBe('passed')
    expect(checkStatus(d, 'envelope.key_binding')).toBe('passed')
    expect(checkStatus(d, 'session.state_match')).toBe('passed')
    expect(checkStatus(d, 'mdoc.device_signature_valid')).toBe('passed')
  })

  it('accepts a response without apv (optional) and says so in the report', async () => {
    const flow = await startFlow()
    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signPresentation(flow)] }, state: flow.state },
      recipientJwk: flow.encryptionJwk,
    })
    await post(flow.verifier, new URLSearchParams({ response: jwe }))
    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'verified') throw new Error('expected verified')
    const binding = status.result.diagnostics.find((check) => check.id === 'envelope.key_binding')
    expect(binding?.status).toBe('passed')
    expect(binding?.detail).toContain('no apv sent')
  })
})

describe('direct_post.jwt — failure modes', () => {
  it('records ENVELOPE_DECRYPTION_FAILED when the JWE was made for another key', async () => {
    const flow = await startFlow()
    const rogue = p256KeyPair()
    const jwe = await encryptWalletResponse({
      payload: { vp_token: {}, state: flow.state },
      recipientJwk: { ...rogue.publicJwk, kid: flow.encryptionJwk.kid },
      apv: flow.nonce,
    })

    const response = await post(flow.verifier, new URLSearchParams({ response: jwe }))
    expect(response.status).toBe(200)

    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(status.result.error?.code).toBe('ENVELOPE_DECRYPTION_FAILED')
    expect(checkStatus(status.result.diagnostics, 'envelope.jwe_decrypted')).toBe('failed')
  })

  it('answers an unroutable kid with 400 and leaves the session intact', async () => {
    const flow = await startFlow()
    const rogue = p256KeyPair()
    const jwe = await encryptWalletResponse({
      payload: { vp_token: {}, state: flow.state },
      recipientJwk: { ...rogue.publicJwk, kid: 'nobody-knows-this-kid' },
    })
    const response = await post(flow.verifier, new URLSearchParams({ response: jwe }))
    expect(response.status).toBe(400)
    expect(await response.json()).toEqual({ error: 'invalid_request' })

    // The pending request survived the probe: the real wallet response still verifies.
    const goodJwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signPresentation(flow)] }, state: flow.state },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })
    await post(flow.verifier, new URLSearchParams({ response: goodJwe }))
    expect((await flow.verifier.getResult(flow.created.sessionId)).status).toBe('verified')
  })

  it('fails the key binding when apv does not encode the request nonce', async () => {
    const flow = await startFlow()
    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signPresentation(flow)] }, state: flow.state },
      recipientJwk: flow.encryptionJwk,
      apv: 'a-different-nonce',
    })
    await post(flow.verifier, new URLSearchParams({ response: jwe }))
    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(status.result.error?.code).toBe('VERIFICATION_FAILED')
    expect(checkStatus(status.result.diagnostics, 'envelope.key_binding')).toBe('failed')
  })

  it('rejects a cleartext vp_token on an encrypted flow — no silent downgrade', async () => {
    const flow = await startFlow()
    const form = new URLSearchParams()
    form.set('state', flow.state)
    form.set('vp_token', JSON.stringify({ av_proof_of_age: [await signPresentation(flow)] }))
    const response = await post(flow.verifier, form)
    expect(response.status).toBe(200)

    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(status.result.error?.code).toBe('ENVELOPE_DECRYPTION_FAILED')
  })

  it('tolerates an unencrypted wallet ERROR on an encrypted flow (spec MAY)', async () => {
    const flow = await startFlow()
    const form = new URLSearchParams()
    form.set('state', flow.state)
    form.set('error', 'access_denied')
    const response = await post(flow.verifier, form)
    expect(response.status).toBe(200)

    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(status.result.error?.code).toBe('USER_DECLINED_OR_NO_CREDENTIAL')
    expect(checkStatus(status.result.diagnostics, 'envelope.jwe_decrypted')).toBe('skipped')
  })

  it('rejects a transcript built without the ephemeral-key thumbprint (§14.5 binding)', async () => {
    const flow = await startFlow()
    const jwe = await encryptWalletResponse({
      payload: {
        vp_token: { av_proof_of_age: [await signPresentation(flow, { thumbprint: null })] },
        state: flow.state,
      },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })
    await post(flow.verifier, new URLSearchParams({ response: jwe }))
    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(checkStatus(status.result.diagnostics, 'mdoc.device_signature_valid')).toBe('failed')
  })

  it('consumes both session keys, so each replay lock stands on its own', async () => {
    // The replay defense rests on two atomic consumptions — the kid index and the request
    // record. A round trip that leaves either key behind still answers a replay with 400
    // (the other lock catches it), so the outcome alone cannot tell the two apart. The store
    // can: after a completed exchange nothing addressable may survive.
    const session = memorySessionAdapter()
    const flow = await startFlow(makeVerifier({ session }))
    const kid = flow.encryptionJwk.kid as string
    expect(await session.get(`${REQUEST_KEY_PREFIX}${flow.state}`)).not.toBeNull()
    expect(await session.get(`${JWE_KID_KEY_PREFIX}${kid}`)).not.toBeNull()

    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signPresentation(flow)] }, state: flow.state },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })
    expect((await post(flow.verifier, new URLSearchParams({ response: jwe }))).status).toBe(200)

    expect(await session.get(`${REQUEST_KEY_PREFIX}${flow.state}`)).toBeNull()
    expect(await session.get(`${JWE_KID_KEY_PREFIX}${kid}`)).toBeNull()
  })

  it('finds nothing on a replayed JWE — atomic consumption covers the kid index too', async () => {
    const flow = await startFlow()
    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signPresentation(flow)] }, state: flow.state },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })
    const first = await post(flow.verifier, new URLSearchParams({ response: jwe }))
    expect(first.status).toBe(200)
    const replay = await post(flow.verifier, new URLSearchParams({ response: jwe }))
    expect(replay.status).toBe(400)
    expect(await replay.json()).toEqual({ error: 'invalid_request' })
  })

  it('fails session.state_match when the decrypted state names another session', async () => {
    const flow = await startFlow()
    const jwe = await encryptWalletResponse({
      payload: {
        vp_token: { av_proof_of_age: [await signPresentation(flow)] },
        state: 'someone-elses-state',
      },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })
    await post(flow.verifier, new URLSearchParams({ response: jwe }))
    const status = await flow.verifier.getResult(flow.created.sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(checkStatus(status.result.diagnostics, 'session.state_match')).toBe('failed')
  })

  it('answers garbage in the response field with 400', async () => {
    const flow = await startFlow()
    for (const junk of ['zzz', 'a.b', 'not.a.jwe.at.all.extra']) {
      const response = await post(flow.verifier, new URLSearchParams({ response: junk }))
      expect(response.status).toBe(400)
    }
    // Still pending — none of that consumed the session.
    expect((await flow.verifier.getResult(flow.created.sessionId)).status).toBe('pending')
  })
})
