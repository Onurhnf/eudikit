/**
 * The default `<AgeGate/>` panel: trigger button, QR / wallet-link block, status line, error
 * line. The markup is deliberately unstyled and semantic, because an age gate lives inside
 * somebody else's design system.
 *
 * What it ships instead of CSS is a styling contract: every meaningful element carries a
 * stable `data-part` name, the root and every part carry `data-state` (the verification
 * status, or `declined` for a verified answer that does not pass), and the root adds
 * `data-channel` once a channel is chosen — so plain CSS like
 * `[data-part="trigger"][data-state="polling"]` reaches any moment of the flow. The
 * `data-eudikit-status` root attribute from earlier releases is kept as well.
 */

import type { ReactElement } from 'react'
import { type EudikitReactLabels, getErrorText } from './labels.js'
import { VerificationQr } from './qr-code.js'
import type { UseVerificationResult, VerificationStatus } from './use-verification.js'

const BUSY: ReadonlySet<VerificationStatus> = new Set<VerificationStatus>([
  'creating',
  'awaiting_wallet',
  'polling',
])

export function DefaultPanel({
  verification,
  labels,
  declined,
  className,
}: {
  verification: UseVerificationResult
  labels: EudikitReactLabels
  declined: boolean
  className?: string
}): ReactElement {
  const { status, channel, qrPayload, deepLink, error, start, cancel } = verification
  const busy = BUSY.has(status)
  // What the styling contract sees. `declined` replaces `verified` on every part: a page
  // styling `[data-state="verified"]` as success must not paint an authentic "no" green.
  const state = declined ? 'declined' : status
  // Both channels carry the same wallet URI; QR is scanned from another device, the link opens
  // a wallet on this one. Once declined the session is settled, so the panel would only invite
  // a scan that can no longer succeed.
  const walletUri = declined ? null : (deepLink ?? qrPayload)

  return (
    <section
      className={className}
      lang={labels.lang}
      data-part="root"
      data-state={state}
      {...(channel !== null ? { 'data-channel': channel } : {})}
      data-eudikit-status={state}
    >
      <button
        type="button"
        data-part="trigger"
        data-state={state}
        onClick={() => {
          void start()
        }}
        disabled={busy}
        aria-busy={busy}
      >
        {labels.trigger}
      </button>

      {walletUri !== null && (
        <div data-part="panel" data-state={state} data-eudikit-panel={channel ?? 'wallet'}>
          {channel === 'qr' && (
            <VerificationQr
              payload={walletUri}
              label={labels.qrLabel}
              data-part="qr"
              data-state={state}
            />
          )}
          <p>
            <a data-part="link" data-state={state} href={walletUri}>
              {labels.openWallet}
            </a>
          </p>
          {channel === 'qr' && (
            <p data-part="hint" data-state={state}>
              {labels.scanQrHint}
            </p>
          )}
        </div>
      )}

      <p role="status" aria-live="polite" data-part="status" data-state={state}>
        {declined ? labels.declined : labels.status[status]}
      </p>

      {error !== null && (
        <p role="alert" data-part="error" data-state={state}>
          {getErrorText(labels, error.code)}
        </p>
      )}

      {busy && (
        <button type="button" data-part="cancel" data-state={state} onClick={cancel}>
          {labels.cancel}
        </button>
      )}
    </section>
  )
}
