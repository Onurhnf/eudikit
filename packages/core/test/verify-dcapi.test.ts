/**
 * `verifier.verify()` — the Digital Credentials API response side, with real wallets simulated
 * over the `OpenID4VPDCAPIHandover` transcript: encrypted (`dc_api.jwt`) and plain (`dc_api`)
 * round trips, origin-allowlist binding, replay, and the throw taxonomy for programming
 * errors.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import { buildOpenID4VPDCAPISessionTranscript } from '../src/mdoc/session-transcript.js'
import type { Check, Verifier, VerifierConfig } from '../src/types.js'
import { expectEudikitError } from './support.js'
import { encryptWalletResponse } from './support-jwe.js'
import {
  FIXED_NOW,
  type IssuerFixture,
  issueAttestation,
  makeIssuer,
  p256KeyPair,
  walletSignResponse,
} from './support-mdoc.js'

const ORIGIN = 'https://shop.example'

const issuer: IssuerFixture = makeIssuer()
const device = p256KeyPair()

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

function makeVerifier(overrides: Partial<VerifierConfig> = {}): Verifier {
  return createVerifier({
    profile: 'eudi',
    session: memorySessionAdapter(),
    expectedOrigins: [ORIGIN],
    trust: { additionalTrustAnchors: [issuer.certificate], avTrustedList: false },
    now: () => FIXED_NOW,
    ...overrides,
  })
}

interface DcApiFlow {
  verifier: Verifier
  sessionId: string
  nonce: string
  encryptionJwk: Record<string, unknown> | null
  protocol: string
}

async function startFlow(
  verifier = makeVerifier(),
  options: { encryptResponse?: boolean } = {}
): Promise<DcApiFlow> {
  const created = await verifier.requests.create({
    preset: presets.age(),
    channel: 'dc-api',
    ...(options.encryptResponse !== undefined ? { encryptResponse: options.encryptResponse } : {}),
  })
  if (created.channel !== 'dc-api') throw new Error('expected dc-api')
  const data = created.dcApiRequest.data as {
    nonce: string
    client_metadata?: { jwks: { keys: [Record<string, unknown>] } }
  }
  return {
    verifier,
    sessionId: created.sessionId,
    nonce: data.nonce,
    encryptionJwk: data.client_metadata?.jwks.keys[0] ?? null,
    protocol: created.dcApiRequest.protocol,
  }
}

/** Signs the wallet's DeviceResponse over the DC API handover for the given origin. */
async function signForOrigin(flow: DcApiFlow, origin: string): Promise<string> {
  const thumbprint =
    flow.encryptionJwk === null
      ? null
      : Uint8Array.from(Buffer.from(flow.encryptionJwk.kid as string, 'base64url'))
  const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
  return walletSignResponse({
    issuerSigned,
    devicePrivateJwk: device.privateJwk,
    sessionTranscript: buildOpenID4VPDCAPISessionTranscript({
      origin,
      nonce: flow.nonce,
      jwkThumbprint: thumbprint,
    }),
  })
}

function checkOf(checks: Check[], id: Check['id']): Check | undefined {
  return checks.find((check) => check.id === id)
}

describe('verify() — encrypted dc_api.jwt round trip', () => {
  it('decrypts, rebuilds the handover per allowed origin and verifies', async () => {
    const flow = await startFlow()
    if (flow.encryptionJwk === null) throw new Error('expected an encryption key')
    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signForOrigin(flow, ORIGIN)] } },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })

    const result = await flow.verifier.verify({
      sessionId: flow.sessionId,
      response: { protocol: 'openid4vp-v1-unsigned', data: { response: jwe } },
    })

    expect(result.verified).toBe(true)
    expect(result.claims).toEqual({ ageOver: true, threshold: 18, source: 'av-attestation' })
    expect(checkOf(result.diagnostics, 'envelope.jwe_decrypted')?.status).toBe('passed')
    expect(checkOf(result.diagnostics, 'envelope.key_binding')?.status).toBe('passed')
    expect(checkOf(result.diagnostics, 'session.origin_allowed')?.status).toBe('passed')
    expect(checkOf(result.diagnostics, 'session.state_match')?.status).toBe('skipped')

    // The outcome is also pollable, exactly like the direct_post channel.
    const status = await flow.verifier.getResult(flow.sessionId)
    expect(status.status).toBe('verified')
  })

  it('tries every allowed origin until the device signature fits', async () => {
    const verifier = makeVerifier({
      expectedOrigins: ['https://other.example', 'android:apk-key-hash:QUFhYQ', ORIGIN],
    })
    const flow = await startFlow(verifier)
    if (flow.encryptionJwk === null) throw new Error('expected an encryption key')
    const jwe = await encryptWalletResponse({
      payload: { vp_token: { av_proof_of_age: [await signForOrigin(flow, ORIGIN)] } },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })
    const result = await verifier.verify({
      sessionId: flow.sessionId,
      response: { protocol: 'openid4vp-v1-unsigned', data: { response: jwe } },
    })
    expect(result.verified).toBe(true)
    expect(checkOf(result.diagnostics, 'session.origin_allowed')?.status).toBe('passed')
  })

  it('rejects a response produced for an origin outside the allowlist', async () => {
    const flow = await startFlow()
    if (flow.encryptionJwk === null) throw new Error('expected an encryption key')
    const jwe = await encryptWalletResponse({
      payload: {
        vp_token: { av_proof_of_age: [await signForOrigin(flow, 'https://evil.example')] },
      },
      recipientJwk: flow.encryptionJwk,
      apv: flow.nonce,
    })
    const result = await flow.verifier.verify({
      sessionId: flow.sessionId,
      response: { protocol: 'openid4vp-v1-unsigned', data: { response: jwe } },
    })
    expect(result.verified).toBe(false)
    expect(checkOf(result.diagnostics, 'session.origin_allowed')?.status).toBe('failed')
    expect(checkOf(result.diagnostics, 'session.origin_allowed')?.detail).toContain(
      'indistinguishable'
    )
  })

  it('records ENVELOPE_DECRYPTION_FAILED for cleartext data on an encrypted request', async () => {
    const flow = await startFlow()
    const result = await flow.verifier.verify({
      sessionId: flow.sessionId,
      response: {
        protocol: 'openid4vp-v1-unsigned',
        data: { vp_token: { av_proof_of_age: ['AAAA'] } },
      },
    })
    expect(result.verified).toBe(false)
    expect(result.error?.code).toBe('ENVELOPE_DECRYPTION_FAILED')
    expect(checkOf(result.diagnostics, 'session.response_mode_match')?.status).toBe('failed')
  })
})

describe('verify() — plain dc_api', () => {
  it('verifies an unencrypted response end to end', async () => {
    const flow = await startFlow(makeVerifier(), { encryptResponse: false })
    expect(flow.encryptionJwk).toBeNull()
    const result = await flow.verifier.verify({
      sessionId: flow.sessionId,
      response: {
        protocol: 'openid4vp-v1-unsigned',
        data: { vp_token: { av_proof_of_age: [await signForOrigin(flow, ORIGIN)] } },
      },
    })
    expect(result.verified).toBe(true)
    expect(checkOf(result.diagnostics, 'envelope.jwe_decrypted')?.status).toBe('skipped')
    expect(checkOf(result.diagnostics, 'session.origin_allowed')?.status).toBe('passed')
  })

  it('maps a wallet error payload onto the honest combined code', async () => {
    const flow = await startFlow(makeVerifier(), { encryptResponse: false })
    const result = await flow.verifier.verify({
      sessionId: flow.sessionId,
      response: { protocol: 'openid4vp-v1-unsigned', data: { error: 'access_denied' } },
    })
    expect(result.verified).toBe(false)
    expect(result.error?.code).toBe('USER_DECLINED_OR_NO_CREDENTIAL')
    expect(result.error?.walletError).toBe('access_denied')
  })
})

describe('verify() — throw taxonomy', () => {
  it('throws SESSION_ALREADY_CONSUMED on the second call for the same session', async () => {
    const flow = await startFlow(makeVerifier(), { encryptResponse: false })
    const data = { vp_token: { av_proof_of_age: [await signForOrigin(flow, ORIGIN)] } }
    await flow.verifier.verify({
      sessionId: flow.sessionId,
      response: { protocol: 'openid4vp-v1-unsigned', data },
    })
    await expectEudikitError(
      () =>
        flow.verifier.verify({
          sessionId: flow.sessionId,
          response: { protocol: 'openid4vp-v1-unsigned', data },
        }),
      'SESSION_ALREADY_CONSUMED'
    )
  })

  it('throws CONFIG_INVALID when no expectedOrigins are configured', async () => {
    const verifier = makeVerifier({ expectedOrigins: [] })
    const flow = await startFlow(verifier, { encryptResponse: false })
    const error = await expectEudikitError(
      () =>
        verifier.verify({
          sessionId: flow.sessionId,
          response: { protocol: 'openid4vp-v1-unsigned', data: { vp_token: {} } },
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('expectedOrigins')
  })

  it('throws CONFIG_INVALID for a QR session id handed to verify()', async () => {
    const verifier = makeVerifier({ publicBaseUrl: 'https://av-demo.example' })
    const created = await verifier.requests.create({
      preset: presets.age(),
      channel: 'qr',
      signedRequest: false,
    })
    const error = await expectEudikitError(
      () =>
        verifier.verify({
          sessionId: created.sessionId,
          response: { protocol: 'openid4vp-v1-unsigned', data: {} },
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('handleWalletResponse')
  })
})
