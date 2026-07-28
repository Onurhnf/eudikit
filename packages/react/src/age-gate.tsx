/**
 * `<AgeGate/>` — the widget: `useVerification()` plus a default panel and the gate itself.
 *
 * The gate separates two questions that must never be conflated: *is the presentation
 * authentic* (the hook's `verified` status) and *is the answer inside it the one this page
 * needs* (the decision). A wallet can truthfully present `age_over_18: false`; that
 * presentation verifies, and the gate must stay closed. `decide` turns the verified claims into
 * the decision — `claims?.ageOver === true` by default — and `children` render only when it
 * passes. A verified negative answer is the `declined` state: not an error (`error` stays
 * `null`), rendered as a neutral line in the status region and marked `data-state="declined"`.
 *
 * Custom UI has two sizes. `fallback` replaces the panel whenever the gate is not passed and
 * keeps the gate behaviour; `children` as a function replaces everything — it receives the hook
 * state plus the resolved labels and the decision, and renders every status itself, `verified`
 * included.
 *
 * All copy comes from the resolved catalog (`locale`/`labels` props); the hook itself carries
 * none. The developer-facing message on `error.message` (which names endpoints and config keys)
 * never reaches the screen: codes without user-facing copy render the catalog's `generic` line,
 * and in development the real code goes to the console instead.
 */

import type { Channel } from '@eudikit/core'
import { type ReactElement, type ReactNode, useEffect, useRef } from 'react'
import { DefaultPanel } from './default-panel.js'
import {
  type EudikitReactLabels,
  type EudikitReactLabelsOverrides,
  getLabels,
  isUserFacingErrorCode,
  type Locale,
} from './labels.js'
import {
  type UseVerificationResult,
  useVerification,
  type VerificationError,
} from './use-verification.js'

/**
 * The gate's verdict, orthogonal to the hook's `status`: `pending` until a presentation
 * verifies, then `passed` or `declined` depending on what `decide` makes of the claims.
 */
export type AgeGateDecision = 'pending' | 'passed' | 'declined'

/** What the `children` and `fallback` render functions receive. */
export interface AgeGateRenderState extends UseVerificationResult {
  /** The catalog resolved from the `locale` and `labels` props. */
  labels: EudikitReactLabels
  /**
   * The gate's verdict over the verified claims. `status === 'verified'` alone is not a reason
   * to unlock anything — check this field (or the claims themselves) as well.
   */
  decision: AgeGateDecision
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
  /**
   * Turns the claims of a verified presentation into the gate decision. A verified
   * presentation is authentic and answers the query that was asked — the answer itself can
   * still be "no". Default: `claims?.ageOver === true`, the shape the `age` preset produces.
   */
  decide?: (claims: Record<string, unknown> | null) => boolean
  /**
   * Called whenever a presentation verifies, whatever the decision — the claims may carry a
   * negative answer. Opening anything from here repeats the mistake `decide` exists to
   * prevent; read the claims.
   */
  onVerified?: (claims: Record<string, unknown>) => void
  onError?: (error: VerificationError) => void
  /**
   * Shown whenever the gate is not passed — unverified and `declined` alike. Default: the
   * button, the QR panel and the status line. The function form receives `decision` and can
   * tell the two apart; a plain node cannot, and shows the same content for both.
   */
  fallback?: ReactNode | ((state: AgeGateRenderState) => ReactNode)
  /**
   * Shown once the gate is passed — the presentation verified *and* `decide` accepted its
   * claims. As a function, the whole UI instead: a render function replaces the default panel
   * and the gate behaviour in every status and decision, `verified` included.
   */
  children: ReactNode | ((state: AgeGateRenderState) => ReactNode)
}

export function AgeGate(props: AgeGateProps): ReactElement {
  const { endpoint, request = 'age', channels, pollIntervalMs, onVerified, onError } = props

  const verification = useVerification({
    endpoint,
    request,
    ...(channels !== undefined ? { channels } : {}),
    ...(pollIntervalMs !== undefined ? { pollIntervalMs } : {}),
  })
  const labels = getLabels(props.locale, props.labels)
  const decision = resolveDecision(verification, props.decide ?? defaultDecide)

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
    return <>{props.children({ ...verification, labels, decision })}</>
  }

  if (decision === 'passed') {
    return <>{props.children}</>
  }

  if (props.fallback !== undefined) {
    const rendered =
      typeof props.fallback === 'function'
        ? props.fallback({ ...verification, labels, decision })
        : props.fallback
    return <>{rendered}</>
  }

  return (
    <DefaultPanel
      verification={verification}
      labels={labels}
      declined={decision === 'declined'}
      {...(props.className !== undefined ? { className: props.className } : {})}
    />
  )
}

function defaultDecide(claims: Record<string, unknown> | null): boolean {
  return claims?.ageOver === true
}

function resolveDecision(
  verification: UseVerificationResult,
  decide: (claims: Record<string, unknown> | null) => boolean
): AgeGateDecision {
  if (verification.status !== 'verified') return 'pending'
  return decide(verification.claims) ? 'passed' : 'declined'
}

// `process` exists under a bundler (which replaces `process.env.NODE_ENV` statically) and in
// tests, but not necessarily in a browser served without one.
declare const process: { env: Record<string, string | undefined> }

function isDevelopment(): boolean {
  return typeof process !== 'undefined' && process.env.NODE_ENV !== 'production'
}
