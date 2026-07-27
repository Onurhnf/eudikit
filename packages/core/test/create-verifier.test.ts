/**
 * `createVerifier()` config resolution and validation.
 *
 * The contract under test: everything that can never be right for any channel fails at
 * `createVerifier()` time with a message naming the offending input, while channel-scoped
 * conditions (public base URL reachability) are deferred to request creation — those live in
 * `create-request.test.ts`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createVerifier, presets } from '../src/index.js'
import type { SessionAdapter, VerifierConfig } from '../src/types.js'
import { expectEudikitError } from './support.js'

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.stubEnv('EUDIKIT_PUBLIC_BASE_URL', '')
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
})

function config(overrides: Partial<VerifierConfig> = {}): VerifierConfig {
  return { profile: 'av', ...overrides }
}

describe('createVerifier — profile', () => {
  it('rejects a missing profile at runtime', async () => {
    const error = await expectEudikitError(
      () => createVerifier({} as unknown as VerifierConfig),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('config.profile')
    expect(error.message).toContain('no default')
  })

  it('rejects an unknown profile value', async () => {
    const error = await expectEudikitError(
      () => createVerifier(config({ profile: 'google' as unknown as 'av' })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('"google"')
  })

  it('rejects a non-object config', async () => {
    await expectEudikitError(
      () => createVerifier(undefined as unknown as VerifierConfig),
      'CONFIG_INVALID'
    )
  })
})

describe('createVerifier — protocolAdapters reservation', () => {
  it('throws CONFIG_UNSUPPORTED_ADAPTER for a non-empty adapter list', async () => {
    const adapter = { protocol: 'org-iso-mdoc' }
    const error = await expectEudikitError(
      () =>
        createVerifier(
          config({
            protocolAdapters: [adapter] as unknown as NonNullable<
              VerifierConfig['protocolAdapters']
            >,
          })
        ),
      'CONFIG_UNSUPPORTED_ADAPTER'
    )
    expect(error.message).toContain('v1.1')
  })

  it('accepts an empty adapter list', () => {
    expect(() => createVerifier(config({ protocolAdapters: [] }))).not.toThrow()
  })
})

describe('createVerifier — expectedOrigins validation', () => {
  it('accepts web origins, localhost dev origins and apk-key-hash origins', () => {
    expect(() =>
      createVerifier(
        config({
          expectedOrigins: [
            'https://shop.example',
            'https://staging.shop.example:8443',
            'http://localhost:3000',
            'android:apk-key-hash:JLl1yF6VpTFTVLGfGTIJsF-2r8mL_lycQzczylnEOLg',
          ],
        })
      )
    ).not.toThrow()
  })

  it('rejects an origin with a path, naming the input and the fix', async () => {
    const error = await expectEudikitError(
      () => createVerifier(config({ expectedOrigins: ['https://shop.example/age'] })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('expectedOrigins[0]')
    expect(error.message).toContain('https://shop.example/age')
    expect(error.message).toContain('"https://shop.example"')
  })

  it('rejects a plain-http origin that is not loopback', async () => {
    const error = await expectEudikitError(
      () => createVerifier(config({ expectedOrigins: ['http://shop.example'] })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('https')
  })

  it('rejects an apk-key-hash with base64 padding', async () => {
    const error = await expectEudikitError(
      () => createVerifier(config({ expectedOrigins: ['android:apk-key-hash:AbC123_-='] })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('apk-key-hash')
    expect(error.message).toContain('base64url')
  })

  it('rejects a string that is neither an origin nor an app origin', async () => {
    const error = await expectEudikitError(
      () => createVerifier(config({ expectedOrigins: ['shop.example'] })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('shop.example')
  })

  it('rejects a non-string entry', async () => {
    const error = await expectEudikitError(
      () => createVerifier(config({ expectedOrigins: [42 as unknown as string] })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('expectedOrigins[0]')
  })
})

describe('createVerifier — publicBaseUrl and TTLs', () => {
  it('rejects a publicBaseUrl that is not a URL at all', async () => {
    const error = await expectEudikitError(
      () => createVerifier(config({ publicBaseUrl: 'not a url' })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('not a url')
  })

  it('accepts an http/localhost publicBaseUrl at construction time (DC API never needs it)', () => {
    expect(() => createVerifier(config({ publicBaseUrl: 'http://localhost:3000' }))).not.toThrow()
  })

  it('rejects non-positive TTLs', async () => {
    await expectEudikitError(
      () => createVerifier(config({ requestTtlSeconds: 0 })),
      'CONFIG_INVALID'
    )
    await expectEudikitError(
      () => createVerifier(config({ resultTtlSeconds: -5 })),
      'CONFIG_INVALID'
    )
  })
})

describe('createVerifier — session adapter', () => {
  it('rejects an adapter that is missing a method', async () => {
    const broken = { set: async () => {}, get: async () => null } as unknown as SessionAdapter
    const error = await expectEudikitError(
      () => createVerifier(config({ session: broken })),
      'CONFIG_INVALID'
    )
    expect(error.message).toContain('consume')
  })

  it('defaults to the in-memory adapter and produces working requests with it', async () => {
    vi.stubEnv('EUDIKIT_PUBLIC_BASE_URL', 'https://tunnel.example')
    const verifier = createVerifier(config())
    const created = await verifier.requests.create({ preset: presets.age(), channel: 'deep-link' })
    expect(created.channel).toBe('deep-link')
  })
})

describe('createVerifier — unimplemented surfaces stay loud', () => {
  it('rejects verify() calls outside the v1 protocol set with UNSUPPORTED_PROTOCOL', async () => {
    const verifier = createVerifier(config())
    for (const protocol of ['org-iso-mdoc', 'openid4vp-v1-multisigned', 'p']) {
      const error = await expectEudikitError(
        () => verifier.verify({ sessionId: 's', response: { protocol, data: null } }),
        'UNSUPPORTED_PROTOCOL'
      )
      expect(error.message).toContain(protocol)
    }
  })

  it('throws SESSION_NOT_FOUND from verify() for an unknown session id', async () => {
    const verifier = createVerifier(config())
    await expectEudikitError(
      () =>
        verifier.verify({
          sessionId: 'never-created',
          response: { protocol: 'openid4vp-v1-unsigned', data: {} },
        }),
      'SESSION_NOT_FOUND'
    )
  })

  it('answers handleRequestUri with an information-free 404 for an unknown session id', async () => {
    const verifier = createVerifier(config())
    const response = await verifier.handleRequestUri(
      new Request('https://verifier.example/api/eudikit/wallet/request/unknown.jwt'),
      'unknown'
    )
    expect(response.status).toBe(404)
    expect(await response.text()).toBe('')
  })
})
