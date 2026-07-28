/**
 * The AV trusted-list layer, in three rings:
 *
 *  (a) the ETSI TS 119 612 parser against the real EU acceptance list (a frozen download in
 *      test/fixtures/ — the suite never touches the network),
 *  (b) the fetch/cache/freshness behavior of `TrustedListSource` with a scripted fetch,
 *  (c) the full verification flow against synthetic lists that contain our fixture DS
 *      certificate, driving the byte-equality match through every status × mode combination.
 */

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import { buildOpenID4VPSessionTranscript } from '../src/mdoc/session-transcript.js'
import { parseTrustedListXml } from '../src/trust/etsi-trusted-list.js'
import { memoryTrustCache, TrustedListSource } from '../src/trust/trusted-list.js'
import type { Check, CreatedRequest, Verifier } from '../src/types.js'
import {
  FIXED_NOW,
  type IssuerFixture,
  issueAttestation,
  makeIssuer,
  p256KeyPair,
  walletSignResponse,
} from './support-mdoc.js'
import { buildTrustedListXml, scriptedFetch } from './support-trusted-list.js'

const FIXTURE_XML = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'av-tl.xml'),
  'utf8'
)

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

// ---------------------------------------------------------------------------
// (a) parser — real EU acceptance list
// ---------------------------------------------------------------------------

describe('parseTrustedListXml — EU acceptance list fixture', () => {
  const parsed = parseTrustedListXml(FIXTURE_XML)

  it('reads the scheme metadata', () => {
    expect(parsed.sequenceNumber).toBe(17)
    expect(parsed.listIssueDateTime).toBe('2026-06-24T12:00:00Z')
    expect(parsed.nextUpdate).toBe('2026-12-16T13:30:00Z')
  })

  it('extracts the twelve current proof-of-age services across seven providers', () => {
    expect(parsed.services).toHaveLength(12)
    expect(new Set(parsed.services.map((service) => service.tspName)).size).toBe(7)
    for (const service of parsed.services) {
      expect(service.serviceTypeIdentifier).toBe(
        'http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa'
      )
    }
  })

  it('normalizes statuses to the last URI segment: 11 recognized + 1 deprecated', () => {
    const recognized = parsed.services.filter((service) => service.status === 'recognized')
    const deprecated = parsed.services.filter((service) => service.status === 'deprecated')
    expect(recognized).toHaveLength(11)
    expect(deprecated).toHaveLength(1)
    expect(deprecated[0]?.serviceName).toBe('Age Verification Issuer')
  })

  it('collects DER certificates from ServiceDigitalIdentity', () => {
    const reference = parsed.services.find(
      (service) => service.serviceName === 'Age Verification DS - 001'
    )
    expect(reference?.status).toBe('recognized')
    expect(reference?.certificates.length).toBeGreaterThan(0)
    for (const service of parsed.services) {
      for (const certificate of service.certificates) {
        expect(certificate[0]).toBe(0x30) // DER SEQUENCE
      }
    }
  })

  it('tolerates a service whose digital identity carries no certificate', () => {
    const parsedEmpty = parseTrustedListXml(
      buildTrustedListXml([
        { tspName: 'T', serviceName: 'S', status: 'recognized', certificates: [] },
      ])
    )
    expect(parsedEmpty.services).toHaveLength(1)
    expect(parsedEmpty.services[0]?.certificates).toHaveLength(0)
  })

  it('ignores ServiceHistoryInstance identities (prior statuses must not resurrect)', () => {
    // The fixture's history instances carry an X509SKI DigitalId and a superseded status;
    // none of them may surface as a current service.
    expect(FIXTURE_XML).toContain('<ServiceHistoryInstance>')
    const names = parsed.services.map((service) => service.serviceName)
    expect(names.filter((name) => name === 'Age Verification Issuer')).toHaveLength(1)
  })

  it('rejects non-list XML and malformed XML', () => {
    expect(() => parseTrustedListXml('<other xmlns="urn:x">nope</other>')).toThrowError(
      /TrustServiceStatusList/
    )
    expect(() => parseTrustedListXml('not xml at all <<<')).toThrowError()
  })
})

// ---------------------------------------------------------------------------
// (b) TrustedListSource — fetch, cache, staleness
// ---------------------------------------------------------------------------

describe('TrustedListSource — cache and freshness', () => {
  const issuer = makeIssuer('Cache DS')
  const xml = buildTrustedListXml([
    {
      tspName: 'Cache TSP',
      serviceName: 'Cache Service',
      status: 'recognized',
      certificates: [issuer.certificate],
    },
  ])

  function source(script: Array<string | Error>, refreshIntervalSeconds = 3600) {
    const scripted = scriptedFetch(script)
    return {
      scripted,
      source: new TrustedListSource({
        url: 'https://lists.example/av-tl.xml',
        refreshIntervalSeconds,
        cache: memoryTrustCache(),
        fetch: scripted.fetch,
      }),
    }
  }

  it('fetches once and serves from cache within the refresh interval', async () => {
    const { scripted, source: tl } = source([xml])
    const first = await tl.getSnapshot(FIXED_NOW)
    const second = await tl.getSnapshot(new Date(FIXED_NOW.getTime() + 30 * 60_000))
    expect(first.available && first.fresh).toBe(true)
    expect(first.services).toHaveLength(1)
    expect(second.fresh).toBe(true)
    expect(scripted.calls()).toBe(1)
  })

  it('refetches after the interval elapses', async () => {
    const { scripted, source: tl } = source([xml, xml])
    await tl.getSnapshot(FIXED_NOW)
    const later = await tl.getSnapshot(new Date(FIXED_NOW.getTime() + 2 * 3600_000))
    expect(later.fresh).toBe(true)
    expect(scripted.calls()).toBe(2)
  })

  it('keeps a cached copy fresh while its own NextUpdate stands, and names the failed refresh', async () => {
    const { source: tl } = source([xml, new Error('connect ETIMEDOUT')])
    await tl.getSnapshot(FIXED_NOW)
    const served = await tl.getSnapshot(new Date(FIXED_NOW.getTime() + 2 * 3600_000))
    expect(served.available).toBe(true)
    expect(served.fresh).toBe(true)
    expect(served.services).toHaveLength(1)
    expect(served.detail).toContain('ETIMEDOUT')
    expect(served.detail).toContain('2026-12-31T00:00:00Z')
  })

  it('marks a cached copy stale once its NextUpdate has passed', async () => {
    const shortLived = buildTrustedListXml(
      [
        {
          tspName: 'Cache TSP',
          serviceName: 'Cache Service',
          status: 'recognized',
          certificates: [issuer.certificate],
        },
      ],
      { nextUpdate: '2026-07-27T13:00:00Z' }
    )
    const { source: tl } = source([shortLived, new Error('connect ETIMEDOUT')])
    await tl.getSnapshot(FIXED_NOW)
    const stale = await tl.getSnapshot(new Date(FIXED_NOW.getTime() + 2 * 3600_000))
    expect(stale.available).toBe(true)
    expect(stale.fresh).toBe(false)
    // Matching still runs against it — the caller decides what a stale list is worth.
    expect(stale.services).toHaveLength(1)
    expect(stale.detail).toContain('has passed')
  })

  it('treats a list with no NextUpdate as stale as soon as a refresh fails', async () => {
    const undated = buildTrustedListXml(
      [
        {
          tspName: 'T',
          serviceName: 'S',
          status: 'recognized',
          certificates: [issuer.certificate],
        },
      ],
      { nextUpdate: '' }
    )
    const { source: tl } = source([undated, new Error('offline')])
    await tl.getSnapshot(FIXED_NOW)
    const stale = await tl.getSnapshot(new Date(FIXED_NOW.getTime() + 2 * 3600_000))
    expect(stale.fresh).toBe(false)
    expect(stale.detail).toContain('absent')
  })

  it("honours the real EU list's NextUpdate on both sides of it", async () => {
    // The frozen acceptance list declares NextUpdate 2026-12-16T13:30:00Z.
    const { source: tl } = source([FIXTURE_XML, new Error('offline'), new Error('offline')])
    await tl.getSnapshot(FIXED_NOW)
    const before = await tl.getSnapshot(new Date('2026-12-16T13:29:00Z'))
    const after = await tl.getSnapshot(new Date('2026-12-16T13:31:00Z'))
    expect(before.fresh).toBe(true)
    expect(after.fresh).toBe(false)
    expect(after.services).toHaveLength(12)
  })

  it('reports unavailable when the fetch fails and no cache exists', async () => {
    const { source: tl } = source([new Error('offline')])
    const snapshot = await tl.getSnapshot(FIXED_NOW)
    expect(snapshot.available).toBe(false)
    expect(snapshot.services).toHaveLength(0)
    expect(snapshot.detail).toContain('offline')
  })

  it('never replaces a good cache with a corrupted download', async () => {
    const { source: tl } = source([xml, 'this is not a trusted list'])
    await tl.getSnapshot(FIXED_NOW)
    const afterBadBody = await tl.getSnapshot(new Date(FIXED_NOW.getTime() + 2 * 3600_000))
    expect(afterBadBody.available).toBe(true)
    expect(afterBadBody.services).toHaveLength(1)
    expect(afterBadBody.detail).toContain('missing root element')
  })

  it('treats a non-200 response as a fetch failure', async () => {
    const failing = async () => new Response('teapot', { status: 418 })
    const tl = new TrustedListSource({
      url: 'https://lists.example/av-tl.xml',
      refreshIntervalSeconds: 3600,
      cache: memoryTrustCache(),
      fetch: failing as unknown as typeof fetch,
    })
    const snapshot = await tl.getSnapshot(FIXED_NOW)
    expect(snapshot.available).toBe(false)
    expect(snapshot.detail).toContain('HTTP 418')
  })

  it("reuses the session adapter's store in 'session-adapter' cache mode", async () => {
    const session = memorySessionAdapter()
    const setSpy = vi.fn(session.set)
    const scripted = scriptedFetch([xml])
    const verifier = createVerifier({
      profile: 'av',
      session: { ...session, set: setSpy },
      trust: { cache: 'session-adapter' },
      fetch: scripted.fetch,
      now: () => FIXED_NOW,
    })
    // Force one verification so the list is pulled through the session-adapter cache.
    await verifier.verifyPresentation({
      format: 'mso_mdoc',
      presentation: 'AAAA',
      bindings: { nonce: 'n', responseUri: 'https://x.example/r' },
    })
    expect(scripted.calls()).toBe(1)
    expect(setSpy.mock.calls.some(([key]) => String(key).startsWith('trust:av-tl:'))).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// (c) end-to-end trust decisions
// ---------------------------------------------------------------------------

const issuer: IssuerFixture = makeIssuer('Listed DS')
const outsider: IssuerFixture = makeIssuer('Unlisted DS')
/** Same subject as the listed DS, different key — membership is bytes, not names. */
const impostor: IssuerFixture = makeIssuer('Listed DS')
const device = p256KeyPair()

const PUBLIC_BASE = 'https://av-demo.example'

interface FlowSetup {
  fetchScript: Array<string | Error>
  mode?: 'strict' | 'permissive'
  anchors?: Uint8Array[]
  refreshIntervalSeconds?: number
  now?: () => Date
}

function makeListVerifier(setup: FlowSetup): { verifier: Verifier; calls: () => number } {
  const scripted = scriptedFetch(setup.fetchScript)
  const verifier = createVerifier({
    profile: 'av',
    publicBaseUrl: PUBLIC_BASE,
    session: memorySessionAdapter(),
    fetch: scripted.fetch,
    trust: {
      ...(setup.mode !== undefined ? { mode: setup.mode } : {}),
      avTrustedList: setup.refreshIntervalSeconds
        ? { refreshIntervalSeconds: setup.refreshIntervalSeconds }
        : true,
      ...(setup.anchors !== undefined ? { additionalTrustAnchors: setup.anchors } : {}),
    },
    now: setup.now ?? (() => FIXED_NOW),
  })
  return { verifier, calls: scripted.calls }
}

/** Full wallet round trip: create a deep-link request, answer it with the given DS. */
async function respond(verifier: Verifier, withIssuer: IssuerFixture): Promise<string> {
  const created: CreatedRequest = await verifier.requests.create({
    preset: presets.age(),
    channel: 'deep-link',
  })
  if (created.channel !== 'deep-link') throw new Error('expected deep-link')
  const params = new URLSearchParams(created.deepLink.slice(created.deepLink.indexOf('?') + 1))
  const issuerSigned = await issueAttestation({
    issuer: withIssuer,
    devicePublicJwk: device.publicJwk,
  })
  const presentation = await walletSignResponse({
    issuerSigned,
    devicePrivateJwk: device.privateJwk,
    sessionTranscript: buildOpenID4VPSessionTranscript({
      clientId: params.get('client_id') ?? '',
      nonce: params.get('nonce') ?? '',
      jwkThumbprint: null,
      responseUri: params.get('response_uri') ?? '',
    }),
  })
  const form = new URLSearchParams()
  form.set('state', params.get('state') ?? '')
  form.set('vp_token', JSON.stringify({ av_proof_of_age: [presentation] }))
  const response = await verifier.handleWalletResponse(
    new Request(`${PUBLIC_BASE}/api/eudikit/wallet/response`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    })
  )
  expect(response.status).toBe(200)
  return created.sessionId
}

function statusOf(checks: Check[], id: Check['id']): Array<Check['status']> {
  return checks.filter((check) => check.id === id).map((check) => check.status)
}

const LISTED_XML = buildTrustedListXml([
  {
    tspName: 'Example Trust Services',
    serviceName: 'Example Age Attestation Service',
    status: 'recognized',
    certificates: [issuer.certificate],
  },
])

const DEPRECATED_XML = buildTrustedListXml([
  {
    tspName: 'Example Trust Services',
    serviceName: 'Example Age Attestation Service',
    status: 'deprecated',
    certificates: [issuer.certificate],
  },
])

describe('trusted list — end-to-end trust decisions', () => {
  it('verifies a DS on the list (recognized) and fills issuer.trustedListEntry', async () => {
    const { verifier } = makeListVerifier({ fetchScript: [LISTED_XML] })
    const sessionId = await respond(verifier, issuer)

    const status = await verifier.getResult(sessionId)
    if (status.status !== 'verified') {
      throw new Error(`expected verified: ${JSON.stringify(status)}`)
    }
    const { result } = status
    expect(statusOf(result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual(['passed'])
    expect(statusOf(result.diagnostics, 'trust.list_fresh')).toEqual(['passed'])
    expect(statusOf(result.diagnostics, 'trust.list_signature_valid')).toEqual(['skipped'])
    expect(statusOf(result.diagnostics, 'trust.chain_valid')).toContain('passed')
    expect(result.credentials[0]?.issuer.trustedListEntry).toEqual({
      tspName: 'Example Trust Services',
      serviceName: 'Example Age Attestation Service',
      status: 'recognized',
    })
  })

  it('rejects a deprecated service in strict mode, warns in permissive', async () => {
    for (const mode of ['strict', 'permissive'] as const) {
      const { verifier } = makeListVerifier({ fetchScript: [DEPRECATED_XML], mode })
      const sessionId = await respond(verifier, issuer)
      const status = await verifier.getResult(sessionId)

      if (mode === 'strict') {
        if (status.status !== 'failed') throw new Error('expected failed')
        expect(statusOf(status.result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual([
          'failed',
        ])
        expect(status.result.error?.code).toBe('VERIFICATION_FAILED')
      } else {
        if (status.status !== 'verified') throw new Error('expected verified')
        expect(status.result.policy).toBe('permissive')
        expect(statusOf(status.result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual([
          'failed',
        ])
      }
      // The membership metadata is reported either way — status included.
      expect(status.result.credentials[0]?.issuer.trustedListEntry?.status).toBe('deprecated')
    }
  })

  it('rejects a DS absent from the list when no anchors vouch for it', async () => {
    const { verifier } = makeListVerifier({ fetchScript: [LISTED_XML] })
    const sessionId = await respond(verifier, outsider)
    const status = await verifier.getResult(sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(statusOf(status.result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual(['failed'])
    expect(statusOf(status.result.diagnostics, 'trust.chain_valid')).toContain('failed')
    expect(status.result.credentials[0]?.issuer.trustedListEntry).toBeNull()
  })

  it('rejects a DS that copies a listed subject but is not the listed certificate', async () => {
    // Membership is decided on the certificate bytes. A distinguished name is free to copy, so
    // a self-signed certificate carrying the listed service's subject must still be a stranger.
    const { verifier } = makeListVerifier({ fetchScript: [LISTED_XML] })
    const sessionId = await respond(verifier, impostor)
    const status = await verifier.getResult(sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(statusOf(status.result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual(['failed'])
    expect(status.result.credentials[0]?.issuer.trustedListEntry).toBeNull()
    // Its own signature is perfectly valid — being self-consistent is not being trusted.
    expect(statusOf(status.result.diagnostics, 'mdoc.issuer_signature_valid')).toEqual(['passed'])
  })

  it('accepts a DS absent from the list but covered by additionalTrustAnchors (union)', async () => {
    const { verifier } = makeListVerifier({
      fetchScript: [LISTED_XML],
      anchors: [outsider.certificate],
    })
    const sessionId = await respond(verifier, outsider)
    const status = await verifier.getResult(sessionId)
    if (status.status !== 'verified') {
      throw new Error(`expected verified: ${JSON.stringify(status)}`)
    }
    // Membership is honestly "no" — but skipped, not failed: the configured anchors vouch.
    expect(statusOf(status.result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual(['skipped'])
    expect(statusOf(status.result.diagnostics, 'trust.chain_valid')).toContain('passed')
  })

  it('fails strict verification with TRUSTED_LIST_UNAVAILABLE when no list and no cache exist', async () => {
    const { verifier } = makeListVerifier({
      fetchScript: [new Error('offline')],
      anchors: [issuer.certificate],
    })
    const sessionId = await respond(verifier, issuer)
    const status = await verifier.getResult(sessionId)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(status.result.error?.code).toBe('TRUSTED_LIST_UNAVAILABLE')
    expect(statusOf(status.result.diagnostics, 'trust.list_fresh')).toEqual(['failed'])
    expect(statusOf(status.result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual(['skipped'])
  })

  it('permissive mode verifies without a list — loudly', async () => {
    const { verifier } = makeListVerifier({
      fetchScript: [new Error('offline')],
      mode: 'permissive',
      anchors: [issuer.certificate],
    })
    const sessionId = await respond(verifier, issuer)
    const status = await verifier.getResult(sessionId)
    if (status.status !== 'verified') throw new Error('expected verified')
    expect(status.result.policy).toBe('permissive')
    expect(statusOf(status.result.diagnostics, 'trust.list_fresh')).toEqual(['failed'])
  })

  it('verifies on a cached list whose NextUpdate still stands when the refresh fails', async () => {
    let clock = FIXED_NOW
    const { verifier } = makeListVerifier({
      fetchScript: [LISTED_XML, new Error('connect ETIMEDOUT')],
      now: () => clock,
    })

    const firstSession = await respond(verifier, issuer)
    expect((await verifier.getResult(firstSession)).status).toBe('verified')

    // The refresh cadence has elapsed and the network is gone, but the list vouches for itself
    // until 2026-12-31 — an outage at the scheme operator does not take verification down.
    clock = new Date(FIXED_NOW.getTime() + 2 * 3600_000)
    const secondSession = await respond(verifier, issuer)
    const status = await verifier.getResult(secondSession)
    if (status.status !== 'verified') {
      throw new Error(`expected verified: ${JSON.stringify(status)}`)
    }
    const freshRow = status.result.diagnostics.find((check) => check.id === 'trust.list_fresh')
    expect(freshRow?.status).toBe('passed')
    expect(freshRow?.detail).toContain('ETIMEDOUT')
  })

  it('rejects in strict mode once the cached list is past its own NextUpdate', async () => {
    let clock = FIXED_NOW
    const expiringXml = buildTrustedListXml(
      [
        {
          tspName: 'Example Trust Services',
          serviceName: 'Example Age Attestation Service',
          status: 'recognized',
          certificates: [issuer.certificate],
        },
      ],
      { nextUpdate: '2026-07-27T13:00:00Z' }
    )
    const { verifier } = makeListVerifier({
      fetchScript: [expiringXml, new Error('connect ETIMEDOUT')],
      now: () => clock,
    })

    const firstSession = await respond(verifier, issuer)
    expect((await verifier.getResult(firstSession)).status).toBe('verified')

    clock = new Date(FIXED_NOW.getTime() + 2 * 3600_000)
    const secondSession = await respond(verifier, issuer)
    const status = await verifier.getResult(secondSession)
    if (status.status !== 'failed') throw new Error('expected failed')
    expect(status.result.error?.code).toBe('VERIFICATION_FAILED')
    const freshRow = status.result.diagnostics.find((check) => check.id === 'trust.list_fresh')
    expect(freshRow?.status).toBe('failed')
    expect(freshRow?.detail).toContain('has passed')
    // Membership itself was still evaluated against the stale data.
    expect(statusOf(status.result.diagnostics, 'trust.issuer_in_trusted_list')).toEqual(['passed'])
  })

  it('shares one fetch across concurrent verifications', async () => {
    const { verifier, calls } = makeListVerifier({ fetchScript: [LISTED_XML] })
    const [a, b] = await Promise.all([respond(verifier, issuer), respond(verifier, issuer)])
    expect((await verifier.getResult(a)).status).toBe('verified')
    expect((await verifier.getResult(b)).status).toBe('verified')
    expect(calls()).toBe(1)
  })
})
