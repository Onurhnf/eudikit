/**
 * `<AgeGate/>` — the widget: `useVerification()` plus a default panel and the gate itself.
 *
 * The markup is deliberately unstyled and semantic, because an age gate lives inside somebody
 * else's design system. What it ships instead of CSS is a styling contract: every meaningful
 * element carries a stable `data-part` name, the root and every part carry `data-state` (the
 * verification status), and the root adds `data-channel` once a channel is chosen — so plain
 * CSS like `[data-part="trigger"][data-state="polling"]` reaches any moment of the flow. The
 * `data-eudikit-status` root attribute from earlier releases is kept as well.
 *
 * Custom UI has two sizes. `fallback` replaces the unverified panel and keeps the gate
 * behaviour; `children` as a function replaces everything — it receives the hook state plus the
 * resolved labels and renders every status itself, `verified` included.
 *
 * All copy comes from the resolved catalog (`locale`/`labels` props); the hook itself carries
 * none. The developer-facing message on `error.message` (which names endpoints and config keys)
 * never reaches the screen: codes without user-facing copy render the catalog's `generic` line,
 * and in development the real code goes to the console instead.
 */

import type { Channel } from '@eudikit/core'
import { type ReactElement, type ReactNode, useEffect, useRef } from 'react'
import {
  type EudikitReactLabels,
  type EudikitReactLabelsOverrides,
  getErrorText,
  getLabels,
  isUserFacingErrorCode,
  type Locale,
} from './labels.js'
import { VerificationQr } from './qr-code.js'
import {
  type UseVerificationResult,
  useVerification,
  type VerificationError,
  type VerificationStatus,
} from './use-verification.js'

/** What the `children` and `fallback` render functions receive. */
export interface AgeGateRenderState extends UseVerificationResult {
  /** The catalog resolved from the `locale` and `labels` props. */
  labels: EudikitReactLabels
}

export interface AgeGateProps {
  /** Base path the core fetch handler is mounted at, e.g. `'/api/eudikit'`. */
  endpoint: string
  /** Name of a request registered in the handler. Default `'age'`. */
  request?: string
  channels?: Channel[]
  pollIntervalMs?: number
  /** Catalog for the built-in copy. Default `'en'`. */
  locale?: Locale
  /** Label overrides, applied field by field on top of the `locale` catalog. */
  labels?: EudikitReactLabelsOverrides
  /** Applied to the panel's root element. */
  className?: string
  onVerified?: (claims: Record<string, unknown>) => void
  onError?: (error: VerificationError) => void
  /** Shown while unverified. Default: the button, the QR panel and the status line. */
  fallback?: ReactNode | ((state: AgeGateRenderState) => ReactNode)
  /**
   * Shown once the gate is passed — or, as a function, the whole UI: a render function
   * replaces the default panel and the gate behaviour in every status, `verified` included.
   */
  children: ReactNode | ((state: AgeGateRenderState) => ReactNode)
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
  const labels = getLabels(props.locale, props.labels)

  // One notification per outcome per attempt: the callbacks are usually inline arrow functions,
  // so the effect itself reruns on every render and the key is what keeps it honest.
  const notifiedRef = useRef<string | null>(null)
  useEffect(() => {
    const { status, claims, error, sessionId } = verification
    if (status !== 'verified' && status !== 'failed') return
    const key = `${sessionId ?? ''}:${status}`
    if (notifiedRef.current === key) return
    notifiedRef.current = key
    if (status === 'verified') {
      onVerified?.(claims ?? {})
      return
    }
    if (error === null) return
    onError?.(error)
    // The generic line hides configuration mistakes from the screen on purpose; put the real
    // code where the developer is looking.
    if (!isUserFacingErrorCode(error.code) && isDevelopment()) {
      console.error(`[eudikit] verification failed with ${error.code}: ${error.message}`)
    }
  }, [verification, onVerified, onError])

  if (typeof props.children === 'function') {
    return <>{props.children({ ...verification, labels })}</>
  }

  if (verification.status === 'verified') {
    return <>{props.children}</>
  }

  if (props.fallback !== undefined) {
    const rendered =
      typeof props.fallback === 'function'
        ? props.fallback({ ...verification, labels })
        : props.fallback
    return <>{rendered}</>
  }

  return (
    <DefaultPanel
      verification={verification}
      labels={labels}
      {...(props.className !== undefined ? { className: props.className } : {})}
    />
  )
}

function DefaultPanel({
  verification,
  labels,
  className,
}: {
  verification: UseVerificationResult
  labels: EudikitReactLabels
  className?: string
}): ReactElement {
  const { status, channel, qrPayload, deepLink, error, start, cancel } = verification
  const busy = BUSY.has(status)
  // Both channels carry the same wallet URI; QR is scanned from another device, the link opens
  // a wallet on this one.
  const walletUri = deepLink ?? qrPayload

  return (
    <section
      className={className}
      lang={labels.lang}
      data-part="root"
      data-state={status}
      {...(channel !== null ? { 'data-channel': channel } : {})}
      data-eudikit-status={status}
    >
      <button
        type="button"
        data-part="trigger"
        data-state={status}
        onClick={() => {
          void start()
        }}
        disabled={busy}
        aria-busy={busy}
      >
        {labels.trigger}
      </button>

      {walletUri !== null && (
        <div data-part="panel" data-state={status} data-eudikit-panel={channel ?? 'wallet'}>
          {channel === 'qr' && (
            <VerificationQr
              payload={walletUri}
              label={labels.qrLabel}
              data-part="qr"
              data-state={status}
            />
          )}
          <p>
            <a data-part="link" data-state={status} href={walletUri}>
              {labels.openWallet}
            </a>
          </p>
          {channel === 'qr' && (
            <p data-part="hint" data-state={status}>
              {labels.scanQrHint}
            </p>
          )}
        </div>
      )}

      <p role="status" aria-live="polite" data-part="status" data-state={status}>
        {labels.status[status]}
      </p>

      {error !== null && (
        <p role="alert" data-part="error" data-state={status}>
          {getErrorText(labels, error.code)}
        </p>
      )}

      {busy && (
        <button type="button" data-part="cancel" data-state={status} onClick={cancel}>
          {labels.cancel}
        </button>
      )}
    </section>
  )
}

// `process` exists under a bundler (which replaces `process.env.NODE_ENV` statically) and in
// tests, but not necessarily in a browser served without one.
declare const process: { env: Record<string, string | undefined> }

function isDevelopment(): boolean {
  return typeof process !== 'undefined' && process.env.NODE_ENV !== 'production'
}
