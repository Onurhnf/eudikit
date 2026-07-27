/**
 * The widget: the default panel's behaviour, the gate itself, and the callbacks. What is
 * asserted here is semantics — roles, live regions, the link a phone can follow — not styling,
 * because the panel deliberately ships none.
 */

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AgeGate } from '../src/age-gate.js'
import type { VerificationError } from '../src/use-verification.js'
import {
  createdQr,
  ENDPOINT,
  installFetch,
  removeDigitalCredentials,
  setVisibility,
  VERIFIED_BODY,
} from './support.js'

beforeEach(() => {
  vi.useFakeTimers()
  removeDigitalCredentials()
  setVisibility('visible')
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

async function clickVerify(): Promise<void> {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /verify your age/i }))
  })
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms)
  })
}

describe('<AgeGate/>', () => {
  it('keeps the gate closed until a verification succeeds, then opens it', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_BODY))
    const onVerified = vi.fn()
    render(
      <AgeGate endpoint={ENDPOINT} onVerified={onVerified}>
        <p>Adults only</p>
      </AgeGate>
    )

    expect(screen.queryByText('Adults only')).toBeNull()
    await clickVerify()
    await advance(1500)

    expect(screen.getByText('Adults only')).not.toBeNull()
    expect(onVerified).toHaveBeenCalledTimes(1)
    expect(onVerified).toHaveBeenCalledWith(VERIFIED_BODY.claims)
  })

  it('renders the QR code and a same-device link once a request exists', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : { status: 'pending' }))
    const { container } = render(
      <AgeGate endpoint={ENDPOINT} className="gate">
        <p>Adults only</p>
      </AgeGate>
    )

    expect(container.querySelector('section')?.className).toBe('gate')
    await clickVerify()

    const link = screen.getByRole('link', { name: /open your wallet/i })
    expect(link.getAttribute('href')).toContain('eudi-openid4vp://authorize')
    expect(container.querySelector('svg[role="img"]')).not.toBeNull()
    expect(
      container.querySelector('[data-eudikit-status]')?.getAttribute('data-eudikit-status')
    ).toBe('polling')
    expect(screen.getByRole('status').textContent).toContain('Waiting for your wallet')
  })

  it('shows user-facing text for a failure and reports the code to onError', async () => {
    installFetch((call) =>
      call.url.endsWith('/requests')
        ? createdQr()
        : {
            status: 'failed',
            verified: false,
            error: {
              code: 'USER_DECLINED_OR_NO_CREDENTIAL',
              message: 'the wallet returned "access_denied"',
            },
          }
    )
    const errors: VerificationError[] = []
    render(
      <AgeGate
        endpoint={ENDPOINT}
        onError={(error) => {
          errors.push(error)
        }}
      >
        <p>Adults only</p>
      </AgeGate>
    )

    await clickVerify()
    await advance(1500)

    // The developer-facing message stays out of the UI; the code drives the copy.
    const alert = screen.getByRole('alert')
    expect(alert.textContent).toContain('Nothing was shared')
    expect(alert.textContent).not.toContain('access_denied')
    expect(errors).toHaveLength(1)
    expect(errors[0]?.code).toBe('USER_DECLINED_OR_NO_CREDENTIAL')
    expect(errors[0]?.message).toContain('access_denied')
  })

  it('lets a custom fallback take over the unverified UI', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_BODY))
    render(
      <AgeGate
        endpoint={ENDPOINT}
        fallback={(verification) => (
          <button type="button" onClick={() => void verification.start()}>
            {verification.status === 'idle' ? 'Prove it' : verification.status}
          </button>
        )}
      >
        <p>Adults only</p>
      </AgeGate>
    )

    const button = screen.getByRole('button', { name: 'Prove it' })
    await act(async () => {
      fireEvent.click(button)
    })
    expect(screen.getByRole('button').textContent).toBe('polling')

    await advance(1500)
    expect(screen.getByText('Adults only')).not.toBeNull()
  })

  it('accepts a plain node as the fallback', () => {
    installFetch(() => createdQr())
    render(
      <AgeGate endpoint={ENDPOINT} fallback={<p>Please verify your age.</p>}>
        <p>Adults only</p>
      </AgeGate>
    )
    expect(screen.getByText('Please verify your age.')).not.toBeNull()
  })
})
