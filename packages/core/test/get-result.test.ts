/**
 * Lifecycle tests for `verifier.getResult` — the polling read is non-destructive, derives its
 * status from which record still exists, and the trust configuration fails loud where the
 * implementation has honest gaps.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, memorySessionAdapter, presets } from '../src/index.js'
import type { VerifierConfig } from '../src/types.js'
import { expectEudikitError } from './support.js'
import { FIXED_NOW } from './support-mdoc.js'

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

function makeVerifier(overrides: Partial<VerifierConfig> = {}) {
  return createVerifier({
    profile: 'av',
    publicBaseUrl: 'https://av-demo.example',
    session: memorySessionAdapter(),
    now: () => FIXED_NOW,
    ...overrides,
  })
}

describe('getResult — lifecycle', () => {
  it('reports pending while the request record is live and unanswered', async () => {
    const verifier = makeVerifier()
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    expect(await verifier.getResult(created.sessionId)).toEqual({ status: 'pending' })
    // Non-destructive: polling twice must not consume anything.
    expect(await verifier.getResult(created.sessionId)).toEqual({ status: 'pending' })
  })

  it('reports expired for a session id that was never issued or has aged out', async () => {
    const verifier = makeVerifier()
    expect(await verifier.getResult('never-issued')).toEqual({ status: 'expired' })
  })

  it('rejects an empty session id', async () => {
    const verifier = makeVerifier()
    await expectEudikitError(() => verifier.getResult(''), 'CONFIG_INVALID')
  })
})

describe('trust configuration', () => {
  it('fails loud when the AV trusted list is explicitly enabled', () => {
    for (const avTrustedList of [true, { url: 'https://example.org/tl.xml' }] as const) {
      const error = (() => {
        try {
          makeVerifier({ trust: { avTrustedList } })
        } catch (caught) {
          return caught as Error
        }
        throw new Error('expected createVerifier to throw')
      })()
      expect(error.message).toContain('AV trusted list fetching')
    }
  })

  it('accepts avTrustedList: false and omitted alike', () => {
    expect(() => makeVerifier({ trust: { avTrustedList: false } })).not.toThrow()
    expect(() => makeVerifier({ trust: {} })).not.toThrow()
  })

  it('rejects a malformed trust mode and malformed anchors', () => {
    expect(() => makeVerifier({ trust: { mode: 'lenient' as unknown as 'strict' } })).toThrowError(
      /strict/
    )
    expect(() =>
      makeVerifier({ trust: { additionalTrustAnchors: ['not a certificate'] } })
    ).toThrowError(/BEGIN CERTIFICATE/)
    expect(() =>
      makeVerifier({ trust: { additionalTrustAnchors: [new Uint8Array(0)] } })
    ).toThrowError(/empty/)
  })

  it('accepts PEM anchors, multi-block bundles included', () => {
    const der = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x01])
    const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString('base64')}\n-----END CERTIFICATE-----\n`
    expect(() =>
      makeVerifier({ trust: { additionalTrustAnchors: [pem + pem, der] } })
    ).not.toThrow()
  })
})
