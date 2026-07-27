/**
 * The hook, driven through its two real paths: the Digital Credentials API round trip and the
 * cross-device QR poll. The handler is a scripted `fetch`, the DC API is a scripted global, and
 * every wait is a fake timer — nothing here sleeps.
 */

import { act, cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { UseVerificationOptions } from '../src/use-verification.js'
import {
  createdDcApi,
  createdQr,
  domError,
  ENDPOINT,
  type FetchCall,
  Harness,
  hook,
  installDigitalCredentials,
  installFetch,
  jsonError,
  removeDigitalCredentials,
  resetHarness,
  setVisibility,
  VERIFIED_BODY,
} from './support.js'

const OPTIONS: UseVerificationOptions = { endpoint: ENDPOINT, request: 'age' }

beforeEach(() => {
  vi.useFakeTimers()
  removeDigitalCredentials()
  setVisibility('visible')
})

afterEach(() => {
  cleanup()
  resetHarness()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

function mount(options = OPTIONS): void {
  render(<Harness options={options} />)
}

async function start(): Promise<void> {
  await act(async () => {
    await hook().start()
  })
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
  })
}

// ---------------------------------------------------------------------------
// channel negotiation
// ---------------------------------------------------------------------------

describe('channel negotiation', () => {
  it('falls back to QR when the browser has no Digital Credentials API', async () => {
    const { calls } = installFetch(() => createdQr())
    mount()
    await start()

    expect(calls).toHaveLength(1)
    expect(calls[0]?.body).toEqual({ name: 'age', channel: 'qr' })
    expect(hook().status).toBe('polling')
    expect(hook().channel).toBe('qr')
    expect(hook().qrPayload).toContain('eudi-openid4vp://authorize')
  })

  it('uses the DC API when the browser allows the protocol', async () => {
    const { calls } = installFetch((call) =>
      call.url.endsWith('/requests') ? createdDcApi() : VERIFIED_BODY
    )
    const dc = installDigitalCredentials()
    mount()
    await start()

    expect(calls[0]?.body).toEqual({ name: 'age', channel: 'dc-api' })
    expect(dc.get).toHaveBeenCalledTimes(1)
    const argument = dc.get.mock.calls[0]?.[0] as {
      digital: { requests: Array<{ protocol: string; data: unknown }> }
      signal?: AbortSignal
    }
    expect(argument.digital.requests[0]?.protocol).toBe('openid4vp-v1-unsigned')
    expect(argument.digital.requests[0]?.data).toMatchObject({ nonce: 'n0nce' })
    expect(argument.signal).toBeInstanceOf(AbortSignal)

    expect(calls[1]?.url).toBe(`${ENDPOINT}/verify`)
    expect(calls[1]?.body).toMatchObject({
      sessionId: 'session-dc',
      response: { protocol: 'openid4vp-v1-unsigned' },
    })
    expect(hook().status).toBe('verified')
    expect(hook().claims).toEqual(VERIFIED_BODY.claims)
  })

  it('falls back to QR when the user agent rejects the protocol the server produced', async () => {
    // Pre-flight passes on the signed protocol, so a request is created; the request comes back
    // unsigned, which this user agent does not allow — that is the second, authoritative check.
    const { calls } = installFetch((call: FetchCall) =>
      (call.body as { channel?: string } | null)?.channel === 'dc-api'
        ? createdDcApi('openid4vp-v1-unsigned')
        : createdQr()
    )
    const dc = installDigitalCredentials({ allows: (p) => p === 'openid4vp-v1-signed' })
    mount()
    await start()

    expect(dc.get).not.toHaveBeenCalled()
    expect(calls.map((call) => call.body)).toEqual([
      { name: 'age', channel: 'dc-api' },
      { name: 'age', channel: 'qr' },
    ])
    expect(hook().status).toBe('polling')
    expect(hook().channel).toBe('qr')
  })

  it('moves on when the server does not serve a channel for this request', async () => {
    const { calls } = installFetch((call) =>
      (call.body as { channel?: string } | null)?.channel === 'dc-api'
        ? jsonError(400, 'channel_not_allowed')
        : createdQr()
    )
    installDigitalCredentials()
    mount()
    await start()

    expect(calls).toHaveLength(2)
    expect(hook().status).toBe('polling')
    expect(hook().error).toBeNull()
  })

  it('reports an unsupported browser when the DC API is the only channel', async () => {
    installFetch(() => createdDcApi())
    mount({ ...OPTIONS, channels: ['dc-api'] })
    await start()

    expect(hook().status).toBe('failed')
    expect(hook().error?.code).toBe('UNSUPPORTED_PROTOCOL')
  })

  it('exposes the deep link without navigating to it', async () => {
    installFetch(() => ({
      channel: 'deep-link',
      sessionId: 'session-dl',
      deepLink: 'eudi-openid4vp://authorize?client_id=x',
      expiresAt: new Date(Date.now() + 900_000).toISOString(),
    }))
    mount({ ...OPTIONS, channels: ['deep-link'] })
    await start()

    expect(hook().channel).toBe('deep-link')
    expect(hook().deepLink).toBe('eudi-openid4vp://authorize?client_id=x')
    expect(hook().qrPayload).toBeNull()
    expect(window.location.href).not.toContain('eudi-openid4vp')
  })
})

// ---------------------------------------------------------------------------
// DC API failure handling
// ---------------------------------------------------------------------------

describe('DC API failures', () => {
  it('maps a declined picker onto USER_DECLINED_OR_NO_CREDENTIAL and stays on the channel', async () => {
    const { calls } = installFetch(() => createdDcApi())
    installDigitalCredentials({
      get: () => Promise.reject(domError('NotAllowedError')),
    })
    mount()
    await start()

    expect(hook().status).toBe('failed')
    expect(hook().error?.code).toBe('USER_DECLINED_OR_NO_CREDENTIAL')
    // No silent QR fallback: the user answered the picker.
    expect(calls).toHaveLength(1)
  })

  it('falls back to QR when the browser refuses the call outright', async () => {
    const { calls } = installFetch((call) =>
      (call.body as { channel?: string } | null)?.channel === 'dc-api'
        ? createdDcApi()
        : createdQr()
    )
    installDigitalCredentials({ get: () => Promise.reject(domError('SecurityError')) })
    mount()
    await start()

    expect(calls).toHaveLength(2)
    expect(hook().status).toBe('polling')
    expect(hook().channel).toBe('qr')
  })

  it('falls back to QR when the wallet was never invoked (wallet_unavailable)', async () => {
    const { calls } = installFetch((call) => {
      if (call.url.endsWith('/verify')) {
        return {
          status: 'failed',
          verified: false,
          error: { code: 'WALLET_UNAVAILABLE', message: 'no wallet answered' },
        }
      }
      return (call.body as { channel?: string } | null)?.channel === 'dc-api'
        ? createdDcApi()
        : createdQr()
    })
    installDigitalCredentials()
    mount()
    await start()

    expect(calls.map((call) => call.url)).toEqual([
      `${ENDPOINT}/requests`,
      `${ENDPOINT}/verify`,
      `${ENDPOINT}/requests`,
    ])
    expect(hook().status).toBe('polling')
    expect(hook().channel).toBe('qr')
  })

  it('reports a wallet rejection from the verify route', async () => {
    installFetch((call) =>
      call.url.endsWith('/verify')
        ? {
            status: 'failed',
            verified: false,
            error: {
              code: 'WALLET_REJECTED_REQUEST',
              message: 'the wallet returned "invalid_request"',
            },
          }
        : createdDcApi()
    )
    installDigitalCredentials()
    mount()
    await start()

    expect(hook().status).toBe('failed')
    expect(hook().error).toEqual({
      code: 'WALLET_REJECTED_REQUEST',
      message: 'the wallet returned "invalid_request"',
    })
  })
})

// ---------------------------------------------------------------------------
// polling
// ---------------------------------------------------------------------------

describe('polling', () => {
  function pollScript(bodies: unknown[]): { calls: FetchCall[] } {
    let index = 0
    return installFetch((call) => {
      if (call.url.endsWith('/requests')) return createdQr()
      const body = bodies[Math.min(index, bodies.length - 1)]
      index += 1
      return body
    })
  }

  it('polls with backoff until the session verifies', async () => {
    const { calls } = pollScript([{ status: 'pending' }, { status: 'pending' }, VERIFIED_BODY])
    mount()
    await start()

    expect(calls).toHaveLength(1)
    await advance(1499)
    expect(calls).toHaveLength(1)
    await advance(1)
    expect(calls).toHaveLength(2)
    expect(calls[1]?.url).toBe(`${ENDPOINT}/sessions/session-qr`)

    // Each pending answer stretches the next wait by half again.
    await advance(2249)
    expect(calls).toHaveLength(2)
    await advance(1)
    expect(calls).toHaveLength(3)

    await advance(3375)
    expect(hook().status).toBe('verified')
    expect(hook().claims).toEqual(VERIFIED_BODY.claims)

    // A settled session is not polled again.
    await advance(20_000)
    expect(calls).toHaveLength(4)
  })

  it('surfaces a failed verification with its code', async () => {
    pollScript([
      {
        status: 'failed',
        verified: false,
        error: {
          code: 'VERIFICATION_FAILED',
          message: 'verification failed: mdoc.value_digests_valid',
        },
      },
    ])
    mount()
    await start()
    await advance(1500)

    expect(hook().status).toBe('failed')
    expect(hook().error?.code).toBe('VERIFICATION_FAILED')
    expect(hook().claims).toBeNull()
  })

  it('reports the server-side expiry status', async () => {
    pollScript([{ status: 'expired' }])
    mount()
    await start()
    await advance(1500)

    expect(hook().status).toBe('expired')
  })

  it('stops on its own once the request has expired', async () => {
    const { calls } = installFetch((call) =>
      call.url.endsWith('/requests') ? createdQr({ ttlMs: 3000 }) : { status: 'pending' }
    )
    mount()
    await start()

    await advance(1500)
    expect(calls).toHaveLength(2)
    // The next tick lands past expiresAt: no request is sent for a session that cannot answer.
    await advance(2250)
    expect(calls).toHaveLength(2)
    expect(hook().status).toBe('expired')
  })

  it('pauses while the tab is hidden and picks up when it returns', async () => {
    const { calls } = installFetch((call) =>
      call.url.endsWith('/requests') ? createdQr() : { status: 'pending' }
    )
    mount()
    await start()

    setVisibility('hidden')
    await advance(10_000)
    expect(calls).toHaveLength(1)

    setVisibility('visible')
    await advance(1500)
    expect(calls).toHaveLength(2)
  })

  it('rides out transport failures and gives up after too many', async () => {
    let polls = 0
    const { calls } = installFetch((call) => {
      if (call.url.endsWith('/requests')) return createdQr()
      polls += 1
      throw new TypeError('Failed to fetch')
    })
    mount()
    await start()

    await advance(60_000)
    expect(polls).toBe(5)
    expect(calls).toHaveLength(6)
    expect(hook().status).toBe('failed')
    expect(hook().error?.code).toBe('INTERNAL')
  })
})

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

describe('lifecycle', () => {
  it('retries a transport failure while creating the request', async () => {
    let attempts = 0
    installFetch(() => {
      attempts += 1
      if (attempts === 1) throw new TypeError('Failed to fetch')
      return createdQr()
    })
    mount()
    // Kicked off outside act(): the retry sleeps on a timer, so the advance below is what
    // drives it, and awaiting the attempt happens inside that scope.
    const started = hook().start()
    await advance(250)
    await act(async () => {
      await started
    })

    expect(attempts).toBe(2)
    expect(hook().status).toBe('polling')
  })

  it('reports an unreachable handler once the retries are spent', async () => {
    installFetch(() => {
      throw new TypeError('Failed to fetch')
    })
    mount()
    // Kicked off outside act(): the retry sleeps on a timer, so the advance below is what
    // drives it, and awaiting the attempt happens inside that scope.
    const started = hook().start()
    await advance(1000)
    await act(async () => {
      await started
    })

    expect(hook().status).toBe('failed')
    expect(hook().error?.code).toBe('INTERNAL')
    expect(hook().error?.message).toContain('/api/eudikit/requests')
  })

  it('cancel() stops polling and returns to idle', async () => {
    const { calls } = installFetch((call) =>
      call.url.endsWith('/requests') ? createdQr() : { status: 'pending' }
    )
    mount()
    await start()
    await advance(1500)
    expect(calls).toHaveLength(2)

    act(() => {
      hook().cancel()
    })
    expect(hook().status).toBe('idle')
    expect(hook().qrPayload).toBeNull()

    await advance(30_000)
    expect(calls).toHaveLength(2)
  })

  it('a second start() abandons the first attempt', async () => {
    const { calls } = installFetch((call) =>
      call.url.endsWith('/requests') ? createdQr() : { status: 'pending' }
    )
    mount()
    await start()
    await start()
    await advance(1500)

    // Two creations, one live poll loop.
    expect(calls.filter((call) => call.url.endsWith('/requests'))).toHaveLength(2)
    expect(calls.filter((call) => call.url.includes('/sessions/'))).toHaveLength(1)
  })

  it('stops polling when the component unmounts', async () => {
    const { calls } = installFetch((call) =>
      call.url.endsWith('/requests') ? createdQr() : { status: 'pending' }
    )
    mount()
    await start()
    cleanup()

    await advance(30_000)
    expect(calls).toHaveLength(1)
  })
})
