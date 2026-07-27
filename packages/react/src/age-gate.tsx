/**
 * `<AgeGate/>` — the widget: `useVerification()` plus a default panel and the gate itself.
 *
 * The markup is deliberately unstyled and semantic. It ships no CSS because an age gate lives
 * inside somebody else's design system; what it does ship is a root `className`, a
 * `data-eudikit-status` attribute to style against, a live region for the status line and an
 * alert region for failures. Any design beyond that is one `fallback` away — pass a node, or a
 * function of the hook state to build a custom panel while keeping the wiring.
 *
 * The user-facing copy here is written for people. The developer-facing message on
 * `error.message` (which names endpoints and config keys) never reaches the screen.
 */

import type { Channel } from '@eudikit/core'
import { type ReactElement, type ReactNode, useEffect, useRef } from 'react'
import { QrCode } from './qr-code.js'
import {
  type UseVerificationResult,
  useVerification,
  type VerificationError,
  type VerificationStatus,
} from './use-verification.js'

export interface AgeGateProps {
  /** Base path the core fetch handler is mounted at, e.g. `'/api/eudikit'`. */
  endpoint: string
  /** Name of a request registered in the handler. Default `'age'`. */
  request?: string
  channels?: Channel[]
  pollIntervalMs?: number
  /** Applied to the panel's root element. */
  className?: string
  onVerified?: (claims: Record<string, unknown>) => void
  onError?: (error: VerificationError) => void
  /** Shown while unverified. Default: the button, the QR panel and the status line. */
  fallback?: ReactNode | ((verification: UseVerificationResult) => ReactNode)
  /** Shown once the gate is passed. */
  children: ReactNode
}

const STATUS_TEXT: Record<VerificationStatus, string> = {
  idle: '',
  creating: 'Preparing the request…',
  awaiting_wallet: 'Waiting for your wallet…',
  polling: 'Waiting for your wallet to answer…',
  verified: 'Verified.',
  failed: '',
  expired: 'This request expired. Start again when you are ready.',
}

const ERROR_TEXT: Partial<Record<VerificationError['code'], string>> = {
  USER_DECLINED_OR_NO_CREDENTIAL:
    'Nothing was shared. Either the request was declined, or your wallet holds no credential ' +
    'that answers it.',
  WALLET_UNAVAILABLE: 'No wallet answered. Scan the QR code with the wallet app on your phone.',
  WALLET_FORMAT_UNSUPPORTED: 'Your wallet cannot present this credential yet.',
  WALLET_REJECTED_REQUEST: 'Your wallet rejected the request.',
  UNSUPPORTED_PROTOCOL: 'This browser cannot talk to a wallet directly. Use the QR code instead.',
  SESSION_ALREADY_CONSUMED: 'That verification was already used. Start a new one.',
  SESSION_NOT_FOUND: 'That verification is no longer available. Start a new one.',
}

const BUSY: ReadonlySet<VerificationStatus> = new Set<VerificationStatus>([
  'creating',
  'awaiting_wallet',
  'polling',
])

export function AgeGate(props: AgeGateProps): ReactElement {
  const { endpoint, request = 'age', channels, pollIntervalMs, onVerified, onError } = props

  const verification = useVerification({
    endpoint,
    request,
    ...(channels !== undefined ? { channels } : {}),
    ...(pollIntervalMs !== undefined ? { pollIntervalMs } : {}),
  })

  // One notification per outcome per attempt: the callbacks are usually inline arrow functions,
  // so the effect itself reruns on every render and the key is what keeps it honest.
  const notifiedRef = useRef<string | null>(null)
  useEffect(() => {
    const { status, claims, error, sessionId } = verification
    if (status !== 'verified' && status !== 'failed') return
    const key = `${sessionId ?? ''}:${status}`
    if (notifiedRef.current === key) return
    notifiedRef.current = key
    if (status === 'verified') onVerified?.(claims ?? {})
    else if (error !== null) onError?.(error)
  }, [verification, onVerified, onError])

  if (verification.status === 'verified') {
    return <>{props.children}</>
  }

  if (props.fallback !== undefined) {
    const rendered =
      typeof props.fallback === 'function' ? props.fallback(verification) : props.fallback
    return <>{rendered}</>
  }

  return (
    <DefaultPanel
      verification={verification}
      {...(props.className !== undefined ? { className: props.className } : {})}
    />
  )
}

function DefaultPanel({
  verification,
  className,
}: {
  verification: UseVerificationResult
  className?: string
}): ReactElement {
  const { status, channel, qrPayload, deepLink, error, start, cancel } = verification
  const busy = BUSY.has(status)
  // Both channels carry the same wallet URI; QR is scanned from another device, the link opens
  // a wallet on this one.
  const walletUri = deepLink ?? qrPayload

  return (
    <section className={className} data-eudikit-status={status}>
      <button
        type="button"
        onClick={() => {
          void start()
        }}
        disabled={busy}
      >
        Verify your age with your wallet
      </button>

      {walletUri !== null && (
        <div data-eudikit-panel={channel ?? 'wallet'}>
          {channel === 'qr' && <QrCode value={walletUri} />}
          <p>
            <a href={walletUri}>Open your wallet app on this device</a>
          </p>
          {channel === 'qr' && <p>Or scan the code with the wallet app on your phone.</p>}
        </div>
      )}

      <p role="status" aria-live="polite">
        {STATUS_TEXT[status]}
      </p>

      {error !== null && (
        <p role="alert">{ERROR_TEXT[error.code] ?? 'Verification could not be completed.'}</p>
      )}

      {busy && (
        <button type="button" onClick={cancel}>
          Cancel
        </button>
      )}
    </section>
  )
}
