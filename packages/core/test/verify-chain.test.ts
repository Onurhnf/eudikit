/**
 * Failure-path tests of the mdoc verification chain: each scenario breaks exactly one link —
 * transcript/nonce binding, value digests, trust anchoring, MSO validity, requested claims —
 * and asserts that precisely the matching check fails and the verdict follows the trust
 * policy. Fixtures are real signed structures throughout; nothing is mocked.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import { buildOpenID4VPSessionTranscript } from '../src/mdoc/session-transcript.js'
import type { Check, CreatedRequest, Verifier, VerifierConfig } from '../src/types.js'
import { expectEudikitError } from './support.js'
import {
  FIXED_NOW,
  type IssuerFixture,
  issueAttestation,
  makeIssuer,
  p256KeyPair,
  walletSignResponse,
} from './support-mdoc.js'

const PUBLIC_BASE = 'https://av-demo.example'

const issuer: IssuerFixture = makeIssuer()
const rogueIssuer: IssuerFixture = makeIssuer('Rogue DS')
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

function deepLinkParams(created: CreatedRequest): URLSearchParams {
  if (created.channel !== 'deep-link') throw new Error('expected a deep-link request')
  return new URLSearchParams(created.deepLink.slice(created.deepLink.indexOf('?') + 1))
}

function transcriptFor(params: URLSearchParams, nonce?: string): Uint8Array {
  return buildOpenID4VPSessionTranscript({
    clientId: params.get('client_id') ?? '',
    nonce: nonce ?? params.get('nonce') ?? '',
    jwkThumbprint: null,
    responseUri: params.get('response_uri') ?? '',
  })
}

async function postPresentation(
  verifier: Verifier,
  created: CreatedRequest,
  presentation: string,
  queryId = 'av_proof_of_age'
): Promise<void> {
  const params = deepLinkParams(created)
  const form = new URLSearchParams({
    state: params.get('state') ?? '',
    vp_token: JSON.stringify({ [queryId]: [presentation] }),
  })
  const response = await verifier.handleWalletResponse(
    new Request(`${PUBLIC_BASE}/api/eudikit/wallet/response`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    })
  )
  expect(response.status).toBe(200)
}

async function failedResult(verifier: Verifier, sessionId: string) {
  const status = await verifier.getResult(sessionId)
  if (status.status !== 'failed') {
    throw new Error(`expected failed, got ${status.status}: ${JSON.stringify(status)}`)
  }
  return status.result
}

function checkStatuses(checks: Check[], id: Check['id']): string[] {
  return checks.filter((check) => check.id === id).map((check) => check.status)
}

// ---------------------------------------------------------------------------
// (b) transcript / nonce binding
// ---------------------------------------------------------------------------

describe('verification chain — nonce and transcript binding', () => {
  it('fails mdoc.device_signature_valid when the wallet signed over a different nonce', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params, 'a-nonce-from-another-exchange'),
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(result.error?.code).toBe('VERIFICATION_FAILED')
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('failed')
    // The issuer half is untouched: only the device binding broke.
    expect(checkStatuses(result.diagnostics, 'mdoc.issuer_signature_valid')).toEqual(['passed'])
    expect(checkStatuses(result.diagnostics, 'mdoc.value_digests_valid')).not.toContain('failed')
  })
})

// ---------------------------------------------------------------------------
// (c) value digest tampering
// ---------------------------------------------------------------------------

describe('verification chain — value digests', () => {
  it('fails mdoc.value_digests_valid when issuer namespaces are swapped under a foreign MSO', async () => {
    const { IssuerSigned } = await import('@owf/mdoc')
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    // Two genuine attestations; the tampered credential carries A's claims under B's MSO —
    // exactly what an attacker rewriting a claim value produces.
    const genuine = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
    const other = await issueAttestation({
      issuer,
      devicePublicJwk: device.publicJwk,
      claims: { age_over_18: false },
    })
    const tampered = IssuerSigned.create({
      issuerNamespaces: genuine.issuerNamespaces,
      issuerAuth: other.issuerAuth,
    })

    const presentation = await walletSignResponse({
      issuerSigned: tampered,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(checkStatuses(result.diagnostics, 'mdoc.value_digests_valid')).toContain('failed')
  })
})

// ---------------------------------------------------------------------------
// (d) trust anchoring — strict vs permissive
// ---------------------------------------------------------------------------

describe('verification chain — trust policy', () => {
  async function respondWithRogueIssuer(verifier: Verifier): Promise<CreatedRequest> {
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)
    const issuerSigned = await issueAttestation({
      issuer: rogueIssuer,
      devicePublicJwk: device.publicJwk,
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    await postPresentation(verifier, created, presentation)
    return created
  }

  it('strict mode rejects a DS certificate that matches no anchor', async () => {
    const verifier = makeVerifier()
    const created = await respondWithRogueIssuer(verifier)

    const result = await failedResult(verifier, created.sessionId)
    expect(result.policy).toBe('strict')
    expect(checkStatuses(result.diagnostics, 'trust.chain_valid')).toContain('failed')
    // The trusted list is disabled in this suite, and the row says so instead of vanishing.
    expect(checkStatuses(result.diagnostics, 'trust.issuer_in_trusted_list')).toContain('skipped')
    // The credential itself is internally sound; only trust failed.
    expect(checkStatuses(result.diagnostics, 'mdoc.issuer_signature_valid')).toEqual(['passed'])
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('passed')
  })

  it('permissive mode verifies but reports the trust failures and names the policy', async () => {
    const verifier = makeVerifier({
      trust: {
        mode: 'permissive',
        additionalTrustAnchors: [issuer.certificate],
        avTrustedList: false,
      },
    })
    const created = await respondWithRogueIssuer(verifier)

    const status = await verifier.getResult(created.sessionId)
    if (status.status !== 'verified') {
      throw new Error(`expected verified, got ${status.status}: ${JSON.stringify(status)}`)
    }
    // A permissive pass can never masquerade as a strict one: the policy is named and the
    // trust failures stay visible as warnings in the report.
    expect(status.result.policy).toBe('permissive')
    expect(checkStatuses(status.result.diagnostics, 'trust.chain_valid')).toContain('failed')
    expect(status.result.claims).toEqual({ ageOver: true, threshold: 18, source: 'av-attestation' })
  })

  it('permissive mode still rejects a broken device signature — only trust relaxes', async () => {
    const verifier = makeVerifier({
      trust: {
        mode: 'permissive',
        additionalTrustAnchors: [issuer.certificate],
        avTrustedList: false,
      },
    })
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)
    const issuerSigned = await issueAttestation({
      issuer: rogueIssuer,
      devicePublicJwk: device.publicJwk,
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params, 'wrong-nonce'),
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(result.policy).toBe('permissive')
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('failed')
  })
})

// ---------------------------------------------------------------------------
// (e) MSO validity window
// ---------------------------------------------------------------------------

describe('verification chain — MSO validity', () => {
  it('fails mdoc.validity_window for an expired MSO', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    const issuerSigned = await issueAttestation({
      issuer,
      devicePublicJwk: device.publicJwk,
      validity: {
        signed: new Date(FIXED_NOW.getTime() - 60 * 86_400_000),
        validFrom: new Date(FIXED_NOW.getTime() - 60 * 86_400_000),
        validUntil: new Date(FIXED_NOW.getTime() - 86_400_000),
      },
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(checkStatuses(result.diagnostics, 'mdoc.validity_window')).toContain('failed')
    expect(result.verified).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// (f) requested claim missing
// ---------------------------------------------------------------------------

describe('verification chain — DCQL post-validation', () => {
  it('fails dcql.claims_present when the presented attestation lacks the requested element', async () => {
    const verifier = makeVerifier()
    // Request age_over_21; the wallet presents an attestation carrying only age_over_18.
    const created = await verifier.requests.create({
      preset: presets.age({ threshold: 21 }),
      channel: 'deep-link',
    })
    const params = deepLinkParams(created)

    const issuerSigned = await issueAttestation({
      issuer,
      devicePublicJwk: device.publicJwk,
      claims: { age_over_18: true },
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    const claimsPresent = result.diagnostics.find(
      (check) => check.id === 'dcql.claims_present' && check.credentialId === 'av_proof_of_age'
    )
    expect(claimsPresent?.status).toBe('failed')
    expect(claimsPresent?.detail).toContain('age_over_21')
    expect(checkStatuses(result.diagnostics, 'dcql.credential_sets_satisfied')).toContain('failed')
    // The chain itself was sound — the wallet answered a different question than asked.
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('passed')
  })

  it('fails dcql.doctype_match when the presented docType differs from the query', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    const issuerSigned = await issueAttestation({
      issuer,
      devicePublicJwk: device.publicJwk,
      docType: 'eu.example.other.1',
      namespace: 'eu.example.other.1',
      claims: { age_over_18: true },
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
      docType: 'eu.example.other.1',
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(checkStatuses(result.diagnostics, 'dcql.doctype_match')).toContain('failed')
  })

  it('rejects a vp_token entry whose query id is not part of the request', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    await postPresentation(verifier, created, presentation, 'a_query_never_asked')

    const result = await failedResult(verifier, created.sessionId)
    expect(checkStatuses(result.diagnostics, 'dcql.credential_sets_satisfied')).toContain('failed')
  })
})

// ---------------------------------------------------------------------------
// verifyPresentation (session-less utility)
// ---------------------------------------------------------------------------

describe('verifyPresentation', () => {
  const BINDINGS = {
    nonce: 'utility-nonce',
    responseUri: 'https://verifier.example/wallet/response',
  }

  async function signedOverBindings(issuerFixture = issuer): Promise<string> {
    const issuerSigned = await issueAttestation({
      issuer: issuerFixture,
      devicePublicJwk: device.publicJwk,
    })
    return walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: buildOpenID4VPSessionTranscript({
        clientId: `redirect_uri:${BINDINGS.responseUri}`,
        nonce: BINDINGS.nonce,
        jwkThumbprint: null,
        responseUri: BINDINGS.responseUri,
      }),
    })
  }

  it('verifies an mso_mdoc presentation against caller-supplied bindings', async () => {
    const verifier = makeVerifier()
    const result = await verifier.verifyPresentation({
      format: 'mso_mdoc',
      presentation: await signedOverBindings(),
      bindings: BINDINGS,
      dcql: presets.age().dcql,
    })
    expect(result.verified).toBe(true)
    expect(result.sessionId).toBe('')
    expect(checkStatuses(result.diagnostics, 'session.found')).toEqual(['skipped'])
  })

  it('fails the device signature when the bindings do not match what the wallet signed', async () => {
    const verifier = makeVerifier()
    const result = await verifier.verifyPresentation({
      format: 'mso_mdoc',
      presentation: await signedOverBindings(),
      bindings: { ...BINDINGS, nonce: 'a-different-nonce' },
    })
    expect(result.verified).toBe(false)
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('failed')
  })

  it('verifies without a dcql query, skipping the doctype comparison', async () => {
    const verifier = makeVerifier()
    const result = await verifier.verifyPresentation({
      format: 'mso_mdoc',
      presentation: await signedOverBindings(),
      bindings: BINDINGS,
    })
    expect(result.verified).toBe(true)
    expect(checkStatuses(result.diagnostics, 'dcql.doctype_match')).toEqual(['skipped'])
    expect(result.claims).toBeNull()
  })

  it('requires a responseUri or an origin binding', async () => {
    const verifier = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.verifyPresentation({
          format: 'mso_mdoc',
          presentation: 'irrelevant',
          bindings: { nonce: 'n' },
        }),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('SessionTranscript')
  })

  it('keeps dc+sd-jwt loud as not implemented', async () => {
    const verifier = makeVerifier()
    const error = await expectEudikitError(
      () =>
        verifier.verifyPresentation({
          format: 'dc+sd-jwt',
          presentation: 'eyJ...~',
          bindings: { nonce: 'n', origin: 'https://shop.example' },
        }),
      'INTERNAL'
    )
    expect(error.message).toContain('SD-JWT')
  })
})
