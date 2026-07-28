/**
 * Failure-path tests of the mdoc verification chain: each scenario breaks exactly one link —
 * transcript/nonce binding, value digests, trust anchoring, MSO validity, requested claims —
 * and asserts that precisely the matching check fails and the verdict follows the trust
 * policy. Fixtures are real signed structures throughout; nothing is mocked.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import { buildOpenID4VPSessionTranscript } from '../src/mdoc/session-transcript.js'
import type { Check, CreatedRequest, DcqlQuery, Verifier, VerifierConfig } from '../src/types.js'
import { expectEudikitError } from './support.js'
import {
  AV_DOCTYPE,
  FIXED_NOW,
  type IssuerFixture,
  issueAttestation,
  makeIssuer,
  p256KeyPair,
  selfSignedCertificate,
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
    // The report may not claim device binding either: nothing proved the presenting device
    // holds the key the MSO attests.
    expect(checkStatuses(result.diagnostics, 'mdoc.device_key_matches_mso')).toContain('failed')
    // A presentation whose chain failed cannot count towards the credential set — the DCQL
    // layer must not paper over a broken signature.
    expect(checkStatuses(result.diagnostics, 'dcql.credential_sets_satisfied')).toEqual(['failed'])
    // The issuer half is untouched: only the device binding broke.
    expect(checkStatuses(result.diagnostics, 'mdoc.issuer_signature_valid')).toEqual(['passed'])
    expect(checkStatuses(result.diagnostics, 'mdoc.value_digests_valid')).not.toContain('failed')
  })
})

// ---------------------------------------------------------------------------
// document envelope: response status, relabelled MSO
// ---------------------------------------------------------------------------

describe('verification chain — document envelope', () => {
  it('fails mdoc.response_status_ok when the wallet reports an error status', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
      // ISO 18013-5 table 8: anything but 0 means the wallet is reporting a problem, and a
      // document riding along with it must not be treated as an answer.
      status: 10,
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(checkStatuses(result.diagnostics, 'mdoc.response_status_ok')).toEqual(['failed'])
    expect(result.verified).toBe(false)
    // The credential inside is sound — only the envelope says otherwise.
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('passed')
    expect(checkStatuses(result.diagnostics, 'mdoc.issuer_signature_valid')).toEqual(['passed'])
  })

  it('fails mdoc.doctype_consistent when a document relabels a foreign MSO', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    // The MSO attests a different doctype; the document claims the one the query asked for. The
    // DCQL comparison reads the document, so only the MSO cross-check can catch the relabelling.
    const issuerSigned = await issueAttestation({
      issuer,
      devicePublicJwk: device.publicJwk,
      docType: 'eu.example.other.1',
      namespace: AV_DOCTYPE,
      claims: { age_over_18: true },
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
      docType: AV_DOCTYPE,
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(checkStatuses(result.diagnostics, 'mdoc.doctype_consistent')).toEqual(['failed'])
    expect(checkStatuses(result.diagnostics, 'dcql.doctype_match')).toEqual(['passed'])
    expect(result.verified).toBe(false)
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

  it('rejects a DS certificate that is past its own validity period', async () => {
    // The anchor is configured and byte-matches, so the only thing wrong is the clock: an
    // expired signer must not keep vouching for credentials. Revocation is out of scope in this
    // release, which leaves this window as the one thing that ages a DS out.
    const expiredKeys = p256KeyPair()
    const expired: IssuerFixture = {
      keys: expiredKeys,
      certificate: selfSignedCertificate(expiredKeys, {
        commonName: 'Expired DS',
        notBefore: new Date(FIXED_NOW.getTime() - 400 * 86_400_000),
        notAfter: new Date(FIXED_NOW.getTime() - 86_400_000),
      }),
    }
    const verifier = makeVerifier({
      trust: { additionalTrustAnchors: [expired.certificate], avTrustedList: false },
    })
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    const params = deepLinkParams(created)

    // Signed while the certificate was still live, so the MSO's own window stays clean.
    const signed = new Date(FIXED_NOW.getTime() - 30 * 86_400_000)
    const issuerSigned = await issueAttestation({
      issuer: expired,
      devicePublicJwk: device.publicJwk,
      validity: { signed, validFrom: signed },
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(checkStatuses(result.diagnostics, 'trust.chain_valid')).toContain('failed')
    // Exactly one link broke: the MSO is inside its own window and the signatures verify.
    expect(checkStatuses(result.diagnostics, 'mdoc.validity_window')).not.toContain('failed')
    expect(checkStatuses(result.diagnostics, 'mdoc.issuer_signature_valid')).toEqual(['passed'])
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
    // A missing claim is a verification failure with a full report, never an extraction error.
    expect(result.error?.code).toBe('VERIFICATION_FAILED')
    const claimsPresent = result.diagnostics.find(
      (check) => check.id === 'dcql.claims_present' && check.credentialId === 'av_proof_of_age'
    )
    expect(claimsPresent?.status).toBe('failed')
    expect(claimsPresent?.detail).toContain('age_over_21')
    expect(checkStatuses(result.diagnostics, 'dcql.claim_types_valid')).toEqual(['skipped'])
    expect(checkStatuses(result.diagnostics, 'dcql.credential_sets_satisfied')).toContain('failed')
    // The chain itself was sound — the wallet answered a different question than asked.
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('passed')
  })

  it('fails dcql.claim_types_valid when the age flag arrives as text instead of a boolean', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({
      preset: presets.age({ threshold: 21 }),
      channel: 'deep-link',
    })
    const params = deepLinkParams(created)

    // A mis-issued credential: the requested attribute exists but was embedded as the string
    // "false" instead of a CBOR boolean.
    const issuerSigned = await issueAttestation({
      issuer,
      devicePublicJwk: device.publicJwk,
      claims: { age_over_21: 'false' },
    })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    await postPresentation(verifier, created, presentation)

    const result = await failedResult(verifier, created.sessionId)
    expect(result.error?.code).toBe('VERIFICATION_FAILED')
    const typesValid = result.diagnostics.find(
      (check) => check.id === 'dcql.claim_types_valid' && check.credentialId === 'av_proof_of_age'
    )
    expect(typesValid?.status).toBe('failed')
    expect(typesValid?.detail).toBe(
      'expected a boolean "age_over_21" claim, received a string ("false") — the credential ' +
        'was issued with a value of the wrong type'
    )
    // The claim was present — only its type is wrong, and the report keeps the two apart.
    expect(checkStatuses(result.diagnostics, 'dcql.claims_present')).toEqual(['passed'])
    expect(checkStatuses(result.diagnostics, 'dcql.credential_sets_satisfied')).toContain('failed')
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('passed')
    expect(checkStatuses(result.diagnostics, 'mdoc.issuer_signature_valid')).toEqual(['passed'])
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

  it('fails a raw query without credential_sets when one of its credentials is missing', async () => {
    // Without credential_sets every credential query must be satisfied (OpenID4VP 1.0 §6.4.2) —
    // a rule with its own code path, reached only by raw dcql queries, never by a preset.
    const dcql: DcqlQuery = {
      credentials: [
        {
          id: 'av_age',
          format: 'mso_mdoc',
          meta: { doctype_value: AV_DOCTYPE },
          claims: [{ path: [AV_DOCTYPE, 'age_over_18'], intent_to_retain: false }],
        },
        {
          id: 'second_credential',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.example.other.1' },
          claims: [{ path: ['eu.example.other.1', 'age_over_18'], intent_to_retain: false }],
        },
      ],
    }
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ dcql, channel: 'deep-link' })
    const params = deepLinkParams(created)

    const issuerSigned = await issueAttestation({ issuer, devicePublicJwk: device.publicJwk })
    const presentation = await walletSignResponse({
      issuerSigned,
      devicePrivateJwk: device.privateJwk,
      sessionTranscript: transcriptFor(params),
    })
    // The wallet answers half the request and stays silent about the rest.
    await postPresentation(verifier, created, presentation, 'av_age')

    const result = await failedResult(verifier, created.sessionId)
    const satisfied = result.diagnostics.find(
      (check) => check.id === 'dcql.credential_sets_satisfied'
    )
    expect(satisfied?.status).toBe('failed')
    expect(satisfied?.detail).toContain('second_credential')
    // The half that did arrive is sound; the request as a whole is not answered.
    expect(checkStatuses(result.diagnostics, 'dcql.claims_present')).toEqual(['passed'])
    expect(checkStatuses(result.diagnostics, 'mdoc.device_signature_valid')).toContain('passed')
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
