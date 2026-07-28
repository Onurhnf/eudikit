/**
 * The widget: the default panel's behaviour, the gate itself, and the callbacks. What is
 * asserted here is semantics — roles, live regions, the link a phone can follow — not styling,
 * because the panel deliberately ships none.
 */

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AgeGate } from '../src/age-gate.js'
import { en, tr } from '../src/locales/index.js'
import type { VerificationError } from '../src/use-verification.js'
import {
  createdQr,
  ENDPOINT,
  installFetch,
  jsonError,
  removeDigitalCredentials,
  setVisibility,
  VERIFIED_BODY,
  VERIFIED_NEGATIVE_BODY,
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
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
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
    // A code with its own copy is not a developer mistake: nothing lands on the console.
    expect(logged.mock.calls.filter((call) => String(call[0]).includes('[eudikit]'))).toHaveLength(
      0
    )
    logged.mockRestore()
  })

  it('shows the generic line for non-user-facing codes, keeps the code, and logs in development', async () => {
    installFetch((call) =>
      call.url.endsWith('/requests') ? jsonError(400, 'unknown_request') : { status: 'pending' }
    )
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
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

    expect(screen.getByRole('alert').textContent).toBe(en.errors.generic)
    expect(errors).toHaveLength(1)
    expect(errors[0]?.code).toBe('CONFIG_INVALID')
    const eudikitLogs = logged.mock.calls.filter((call) => String(call[0]).includes('[eudikit]'))
    expect(eudikitLogs).toHaveLength(1)
    expect(String(eudikitLogs[0]?.[0])).toContain('CONFIG_INVALID')
    logged.mockRestore()
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

describe('<AgeGate/> decision', () => {
  it('keeps the gate closed on an authentic negative answer, without treating it as an error', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_NEGATIVE_BODY))
    const onVerified = vi.fn()
    const onError = vi.fn()
    const { container } = render(
      <AgeGate endpoint={ENDPOINT} onVerified={onVerified} onError={onError}>
        <p>Adults only</p>
      </AgeGate>
    )

    await clickVerify()
    await advance(1500)

    // The presentation verified — the wallet's answer was simply "no". The gate stays closed.
    expect(screen.queryByText('Adults only')).toBeNull()
    expect(container.querySelector('[data-part="root"]')?.getAttribute('data-state')).toBe(
      'declined'
    )
    expect(screen.getByRole('status').textContent).toBe(en.declined)
    // Not a failure: no alert, no error callback — but the machine truth still reaches
    // onVerified, negative claims included.
    expect(screen.queryByRole('alert')).toBeNull()
    expect(onError).not.toHaveBeenCalled()
    expect(onVerified).toHaveBeenCalledTimes(1)
    expect(onVerified).toHaveBeenCalledWith(VERIFIED_NEGATIVE_BODY.claims)
  })

  it('opens the gate only for a passing answer, with no declined line in sight', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_BODY))
    render(
      <AgeGate endpoint={ENDPOINT}>
        <p>Adults only</p>
      </AgeGate>
    )

    await clickVerify()
    await advance(1500)

    expect(screen.getByText('Adults only')).not.toBeNull()
    expect(screen.queryByText(en.declined)).toBeNull()
  })

  it('lets decide replace the default policy', async () => {
    const countryBody = {
      status: 'verified',
      verified: true,
      claims: { attribute: 'nationality', countries: ['DE', 'FR'] },
    }
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : countryBody))
    render(
      <AgeGate
        endpoint={ENDPOINT}
        decide={(claims) => Array.isArray(claims?.countries) && claims.countries.includes('DE')}
      >
        <p>Willkommen</p>
      </AgeGate>
    )

    await clickVerify()
    await advance(1500)

    expect(screen.getByText('Willkommen')).not.toBeNull()
  })

  it('declines when decide rejects claims the default policy would pass', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_BODY))
    render(
      <AgeGate endpoint={ENDPOINT} decide={() => false}>
        <p>Adults only</p>
      </AgeGate>
    )

    await clickVerify()
    await advance(1500)

    expect(screen.queryByText('Adults only')).toBeNull()
    expect(screen.getByRole('status').textContent).toBe(en.declined)
  })
})

describe('<AgeGate/> render prop', () => {
  it('hands the hook state plus resolved labels to children and renders no default UI', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_BODY))
    const { container } = render(
      <AgeGate endpoint={ENDPOINT} locale="tr">
        {(state) => (
          <div>
            <button
              type="button"
              onClick={() => {
                void state.start()
              }}
            >
              {state.labels.trigger}
            </button>
            <output>{state.status}</output>
            {state.status === 'verified' && <p>Kapı açık</p>}
          </div>
        )}
      </AgeGate>
    )

    // The function owns the whole surface: none of the default panel's parts exist.
    expect(container.querySelector('[data-part]')).toBeNull()
    const button = screen.getByRole('button', { name: tr.trigger })

    await act(async () => {
      fireEvent.click(button)
    })
    expect(container.querySelector('output')?.textContent).toBe('polling')
    expect(container.querySelector('[data-part]')).toBeNull()

    await advance(1500)
    // The verified state is the function's to render too — no automatic children swap.
    expect(container.querySelector('output')?.textContent).toBe('verified')
    expect(screen.getByText('Kapı açık')).not.toBeNull()
  })

  it('hands the decision alongside the status, so a custom UI can tell "authentic" from "passing"', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_NEGATIVE_BODY))
    const { container } = render(
      <AgeGate endpoint={ENDPOINT}>
        {(state) => (
          <div>
            <button
              type="button"
              onClick={() => {
                void state.start()
              }}
            >
              go
            </button>
            <output>{`${state.status}/${state.decision}`}</output>
            {state.decision === 'declined' && <p>{state.labels.declined}</p>}
            {state.error !== null && <p role="alert">boom</p>}
          </div>
        )}
      </AgeGate>
    )
    const outcome = (): string | undefined => container.querySelector('output')?.textContent

    expect(outcome()).toBe('idle/pending')
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'go' }))
    })
    expect(outcome()).toBe('polling/pending')

    await advance(1500)
    expect(outcome()).toBe('verified/declined')
    expect(screen.getByText(en.declined)).not.toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('reports a passing decision next to the verified status', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : VERIFIED_BODY))
    const { container } = render(
      <AgeGate endpoint={ENDPOINT}>
        {(state) => (
          <div>
            <button
              type="button"
              onClick={() => {
                void state.start()
              }}
            >
              go
            </button>
            <output>{`${state.status}/${state.decision}`}</output>
          </div>
        )}
      </AgeGate>
    )

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'go' }))
    })
    await advance(1500)

    expect(container.querySelector('output')?.textContent).toBe('verified/passed')
  })
})

describe('<AgeGate/> labels and locale', () => {
  it('renders a locale catalog and marks the language on the root', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : { status: 'pending' }))
    const { container } = render(
      <AgeGate endpoint={ENDPOINT} locale="tr">
        <p>İçerik</p>
      </AgeGate>
    )

    expect(container.querySelector('[data-part="root"]')?.getAttribute('lang')).toBe('tr')
    const button = screen.getByRole('button', { name: tr.trigger })
    await act(async () => {
      fireEvent.click(button)
    })

    expect(screen.getByRole('status').textContent).toBe(tr.status.polling)
    expect(screen.getByText(tr.scanQrHint)).not.toBeNull()
    expect(screen.getByText(tr.openWallet)).not.toBeNull()
    expect(container.querySelector('svg')?.getAttribute('aria-label')).toBe(tr.qrLabel)
    expect(screen.getByRole('button', { name: tr.cancel })).not.toBeNull()
  })

  it('lets labels overrides beat the locale catalog field by field', async () => {
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : { status: 'pending' }))
    render(
      <AgeGate
        endpoint={ENDPOINT}
        locale="tr"
        labels={{ trigger: 'Kanıtla', status: { polling: 'Cüzdan yolda' } }}
      >
        <p>İçerik</p>
      </AgeGate>
    )

    const button = screen.getByRole('button', { name: 'Kanıtla' })
    await act(async () => {
      fireEvent.click(button)
    })

    expect(screen.getByRole('status').textContent).toBe('Cüzdan yolda')
    // Untouched fields still come from the locale catalog.
    expect(screen.getByRole('button', { name: tr.cancel })).not.toBeNull()
  })
})

describe('<AgeGate/> styling contract', () => {
  it('exposes data-part, data-state and data-channel through the flow', async () => {
    let result: unknown = { status: 'pending' }
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : result))
    const { container } = render(
      <AgeGate endpoint={ENDPOINT}>
        <p>Adults only</p>
      </AgeGate>
    )
    const part = (name: string): Element | null => container.querySelector(`[data-part="${name}"]`)

    expect(part('root')?.getAttribute('data-state')).toBe('idle')
    expect(part('root')?.hasAttribute('data-channel')).toBe(false)
    expect(part('trigger')?.getAttribute('data-state')).toBe('idle')
    expect(part('trigger')?.getAttribute('aria-busy')).toBe('false')
    expect(part('qr')).toBeNull()
    expect(part('cancel')).toBeNull()

    await clickVerify()

    expect(part('root')?.getAttribute('data-state')).toBe('polling')
    expect(part('root')?.getAttribute('data-channel')).toBe('qr')
    expect(part('trigger')?.getAttribute('data-state')).toBe('polling')
    expect(part('trigger')?.getAttribute('aria-busy')).toBe('true')
    expect(part('trigger')?.hasAttribute('disabled')).toBe(true)
    expect(part('panel')?.getAttribute('data-state')).toBe('polling')
    expect(part('qr')?.tagName.toLowerCase()).toBe('svg')
    expect(part('qr')?.getAttribute('data-state')).toBe('polling')
    expect(part('link')?.getAttribute('href')).toContain('eudi-openid4vp://')
    expect(part('hint')?.textContent).toBe(en.scanQrHint)
    expect(part('status')?.getAttribute('data-state')).toBe('polling')
    expect(part('cancel')).not.toBeNull()

    result = { status: 'failed', verified: false, error: { code: 'WALLET_REJECTED_REQUEST' } }
    await advance(1500)

    expect(part('root')?.getAttribute('data-state')).toBe('failed')
    expect(part('error')?.getAttribute('data-state')).toBe('failed')
    expect(part('error')?.textContent).toBe(en.errors.WALLET_REJECTED_REQUEST)
    expect(part('cancel')).toBeNull()
  })

  it('marks every part declined when a verified answer does not pass', async () => {
    let result: unknown = { status: 'pending' }
    installFetch((call) => (call.url.endsWith('/requests') ? createdQr() : result))
    const { container } = render(
      <AgeGate endpoint={ENDPOINT}>
        <p>Adults only</p>
      </AgeGate>
    )
    const part = (name: string): Element | null => container.querySelector(`[data-part="${name}"]`)

    await clickVerify()
    expect(part('qr')).not.toBeNull()

    result = VERIFIED_NEGATIVE_BODY
    await advance(1500)

    // `declined` replaces `verified` on the whole contract, legacy attribute included — CSS
    // keyed on the verified state must not reach an authentic "no".
    expect(part('root')?.getAttribute('data-state')).toBe('declined')
    expect(part('root')?.getAttribute('data-eudikit-status')).toBe('declined')
    expect(part('trigger')?.getAttribute('data-state')).toBe('declined')
    expect(part('trigger')?.hasAttribute('disabled')).toBe(false)
    expect(part('status')?.getAttribute('data-state')).toBe('declined')
    expect(part('status')?.textContent).toBe(en.declined)
    // The session is settled: no stale QR inviting a second scan, no cancel, and no alert.
    expect(part('panel')).toBeNull()
    expect(part('qr')).toBeNull()
    expect(part('cancel')).toBeNull()
    expect(part('error')).toBeNull()
    expect(screen.queryByText('Adults only')).toBeNull()
  })

  it('keeps the status line a polite live region and the root in the catalog language', () => {
    installFetch(() => createdQr())
    const { container } = render(
      <AgeGate endpoint={ENDPOINT}>
        <p>Adults only</p>
      </AgeGate>
    )

    expect(screen.getByRole('status').getAttribute('aria-live')).toBe('polite')
    expect(container.querySelector('[data-part="root"]')?.getAttribute('lang')).toBe('en')
    // The pre-render attribute from earlier releases stays alongside the new contract.
    expect(
      container.querySelector('[data-eudikit-status]')?.getAttribute('data-eudikit-status')
    ).toBe('idle')
  })
})
