/**
 * `@eudikit/react` — transport and UI only.
 *
 * This package never verifies anything. It calls the Digital Credentials API, falls back to a QR
 * code, polls for a result, and renders. Every cryptographic decision happens on the server, in
 * `@eudikit/core`: verification in the client would be no verification at all.
 *
 * STATUS: skeleton — both entry points throw.
 */

import type { Channel, EudikitErrorCode } from '@eudikit/core'
import { EudikitError } from '@eudikit/core'
import type { ReactElement, ReactNode } from 'react'

function notImplemented(surface: string): never {
  throw new EudikitError(
    'INTERNAL',
    `${surface} is not implemented yet — @eudikit/react is a pre-release skeleton.`
  )
}

export interface UseVerificationOptions {
  /** Base path the core fetch handler is mounted at, e.g. `'/api/eudikit'`. */
  endpoint: string
  /** Name of a request registered in the handler, e.g. `'age'`. */
  request: string
  /** Preference order. Default `['dc-api', 'qr']`: use the DC API when available, QR otherwise. */
  channels?: Channel[]
  /** Default 1500 ms, with backoff. Polling pauses while the tab is hidden. */
  pollIntervalMs?: number
}

export interface UseVerificationResult {
  status: 'idle' | 'creating' | 'awaiting_wallet' | 'polling' | 'verified' | 'failed' | 'expired'
  /**
   * MUST be called from a user gesture: the Digital Credentials API consumes transient
   * activation, and a call outside a click handler fails.
   */
  start: () => Promise<void>
  cancel: () => void
  /** The channel actually chosen. */
  channel: Channel | null
  /** The string to render as a QR code while `channel === 'qr'`. */
  qrPayload: string | null
  deepLink: string | null
  claims: Record<string, unknown> | null
  /** Includes the deliberately combined `USER_DECLINED_OR_NO_CREDENTIAL`. */
  error: { code: EudikitErrorCode; message: string } | null
}

/**
 * The headless hook — this is the real API; `<AgeGate/>` is sugar on top of it.
 *
 * It owns the browser-side details: the `typeof DigitalCredential` guard,
 * `userAgentAllowsProtocol()` negotiation, mapping `NotAllowedError` to
 * `USER_DECLINED_OR_NO_CREDENTIAL`, `AbortSignal`, and the automatic fall back to QR.
 */
export function useVerification(_options: UseVerificationOptions): UseVerificationResult {
  return notImplemented('useVerification()')
}

export interface AgeGateProps {
  endpoint: string
  /** Default `'age'`. */
  request?: string
  channels?: Channel[]
  onVerified?: (claims: Record<string, unknown>) => void
  onError?: (error: { code: EudikitErrorCode }) => void
  /** Shown while unverified. Default: a button plus the QR panel. */
  fallback?: ReactNode
  /** Shown once the gate is passed. */
  children: ReactNode
}

export function AgeGate(_props: AgeGateProps): ReactElement {
  return notImplemented('<AgeGate/>')
}
