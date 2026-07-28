/**
 * `useVerification()` — the headless hook. `<AgeGate/>` is sugar on top of it.
 *
 * It owns four things the integrator should not have to:
 *
 *  - **Channel negotiation.** The preference list is walked in order; a channel that this
 *    browser (or the server's request registry) cannot serve is skipped, so the DC API is used
 *    where it exists and the QR flow carries everyone else. Nothing is announced to the user
 *    until a channel is actually running.
 *  - **Transient activation.** `start()` reaches `navigator.credentials.get()` through its own
 *    promise chain — one server round trip, no timers, no deferred work. Call it from a click
 *    handler; a call outside a user gesture fails with `NotAllowedError`, by design.
 *  - **Waiting.** Cross-device flows poll, with backoff, and stop polling while the tab is
 *    hidden — a phone that is showing the wallet is not showing this page, so a background tab
 *    hammering the server buys nothing.
 *  - **Honest errors.** Everything the wallet, browser or server can produce lands in one
 *    `{ code, message }`, including the deliberately combined
 *    `USER_DECLINED_OR_NO_CREDENTIAL`.
 *
 * Nothing here verifies anything and nothing here navigates: `deepLink` is exposed for the UI
 * to render as a link, because a hook that changes `location` out from under a click is a hook
 * nobody can compose with.
 */

import type { Channel, EudikitErrorCode } from '@eudikit/core'
import { useCallback, useEffect, useRef, useState } from 'react'
import {
  createRequest,
  describeCode,
  type ResultBody,
  type SerializedCreatedRequest,
  toVerificationError,
} from './client.js'
import { dcApiUsable, runDcApi } from './dc-api-run.js'
import { beginPolling, type PollRunner } from './polling.js'

export type VerificationStatus =
  | 'idle'
  | 'creating'
  | 'awaiting_wallet'
  | 'polling'
  | 'verified'
  | 'failed'
  | 'expired'

export interface VerificationError {
  code: EudikitErrorCode
  message: string
}

export interface UseVerificationOptions {
  /** Base path the core fetch handler is mounted at, e.g. `'/api/eudikit'`. */
  endpoint: string
  /** Name of a request registered in the handler, e.g. `'age'`. */
  request: string
  /**
   * Preference order. Default `['dc-api', 'qr']`: use the Digital Credentials API where the
   * browser has it, QR otherwise. Today's EU AV wallet is reached through `'qr'` and
   * `'deep-link'` — it does not answer `openid4vp-v1-*` over the DC API.
   */
  channels?: Channel[]
  /**
   * Base interval for the cross-device poll. Default 1500 ms; each pending answer stretches the
   * next wait by half again, up to eight seconds.
   */
  pollIntervalMs?: number
}

export interface UseVerificationResult {
  /**
   * `'verified'` means the presentation was verified — authentic, bound to this session,
   * matching the query. It says nothing about whether the answer satisfies your policy: a
   * wallet can truthfully present `age_over_18: false`, and that presentation verifies. The
   * answer lives in `claims`; deciding what it is worth is the UI layer's job, not this hook's.
   */
  status: VerificationStatus
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
  /** The wallet URI to link to while `channel === 'deep-link'`; never navigated to for you. */
  deepLink: string | null
  claims: Record<string, unknown> | null
  /** Includes the deliberately combined `USER_DECLINED_OR_NO_CREDENTIAL`. */
  error: VerificationError | null
  /** The session the current attempt belongs to — useful for logs and support. */
  sessionId: string | null
}

const DEFAULT_CHANNELS: Channel[] = ['dc-api', 'qr']

/** One attempt's whole state; the channel runners patch it through the `apply` callback. */
export interface VerificationState {
  status: VerificationStatus
  channel: Channel | null
  qrPayload: string | null
  deepLink: string | null
  claims: Record<string, unknown> | null
  error: VerificationError | null
  sessionId: string | null
}

const IDLE: VerificationState = {
  status: 'idle',
  channel: null,
  qrPayload: null,
  deepLink: null,
  claims: null,
  error: null,
  sessionId: null,
}

export function useVerification(options: UseVerificationOptions): UseVerificationResult {
  const [state, setState] = useState<VerificationState>(IDLE)

  // The options are read through a ref so that `start` and the poll loop always see the current
  // values without the callback identity changing on every render.
  const optionsRef = useRef<UseVerificationOptions>(options)
  useEffect(() => {
    optionsRef.current = options
  })

  const runRef = useRef(0)
  const abortRef = useRef<AbortController | null>(null)
  const pollRef = useRef<PollRunner | null>(null)
  const mountedRef = useRef(true)

  const stopRun = useCallback(() => {
    pollRef.current?.stop()
    pollRef.current = null
    abortRef.current?.abort()
    abortRef.current = null
  }, [])

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      stopRun()
    }
  }, [stopRun])

  // One listener for the whole hook: the runner decides whether it has anything to resume.
  useEffect(() => {
    if (typeof document === 'undefined') return
    const onVisibility = (): void => {
      if (document.visibilityState === 'visible') pollRef.current?.resume()
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [])

  const cancel = useCallback(() => {
    runRef.current += 1
    stopRun()
    if (mountedRef.current) setState(IDLE)
  }, [stopRun])

  const start = useCallback(async (): Promise<void> => {
    const settings = optionsRef.current
    stopRun()
    runRef.current += 1
    const run = runRef.current
    const controller = new AbortController()
    abortRef.current = controller

    const isCurrent = (): boolean => runRef.current === run && mountedRef.current
    const apply = (patch: Partial<VerificationState>): void => {
      if (isCurrent()) setState((previous) => ({ ...previous, ...patch }))
    }
    const settle = (body: ResultBody): void => {
      apply(resultPatch(body))
    }
    const fail = (failure: VerificationError): void => {
      apply({ status: 'failed', error: failure, claims: null })
    }

    setState({ ...IDLE, status: 'creating' })

    const order = resolveChannels(settings.channels)
    let blocked: VerificationError | null = null

    for (let index = 0; index < order.length; index += 1) {
      const channel = order[index] as Channel
      const isLast = index === order.length - 1

      if (channel === 'dc-api' && !dcApiUsable()) {
        blocked = {
          code: 'UNSUPPORTED_PROTOCOL',
          message: 'this browser does not support the Digital Credentials API',
        }
        continue
      }

      let created: SerializedCreatedRequest
      try {
        created = await createRequest({
          endpoint: settings.endpoint,
          name: settings.request,
          channel,
          signal: controller.signal,
        })
      } catch (cause) {
        if (!isCurrent()) return
        const failure = toVerificationError(cause)
        // A channel the server does not serve for this request is a negotiation outcome, not
        // an error — as long as there is somewhere left to go.
        if (failure.code === 'CHANNEL_PROFILE_MISMATCH' && !isLast) {
          blocked = failure
          continue
        }
        fail(failure)
        return
      }
      if (!isCurrent()) return

      if (created.channel === 'dc-api') {
        const outcome = await runDcApi({
          created,
          endpoint: settings.endpoint,
          signal: controller.signal,
          isCurrent,
          apply,
          settle,
          fail,
        })
        if (outcome.done) return
        blocked = outcome.reason
        continue
      }

      beginPolling({
        created,
        settings,
        controller,
        run,
        isCurrent,
        apply,
        settle,
        fail,
        pollRef,
      })
      return
    }

    fail(
      blocked ?? {
        code: 'WALLET_UNAVAILABLE',
        message: 'no verification channel is available in this browser',
      }
    )
  }, [stopRun])

  return {
    status: state.status,
    start,
    cancel,
    channel: state.channel,
    qrPayload: state.qrPayload,
    deepLink: state.deepLink,
    claims: state.claims,
    error: state.error,
    sessionId: state.sessionId,
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function resolveChannels(channels: Channel[] | undefined): Channel[] {
  if (channels === undefined) return DEFAULT_CHANNELS
  const filtered = channels.filter(
    (channel) => channel === 'dc-api' || channel === 'qr' || channel === 'deep-link'
  )
  return filtered.length === 0 ? DEFAULT_CHANNELS : filtered
}

function resultPatch(body: ResultBody): Partial<VerificationState> {
  if (body.status === 'verified') {
    return { status: 'verified', claims: body.claims ?? {}, error: null }
  }
  if (body.status === 'expired') {
    return { status: 'expired', claims: null }
  }
  const code = body.error?.code ?? 'VERIFICATION_FAILED'
  return {
    status: 'failed',
    claims: null,
    error: { code, message: body.error?.message ?? describeCode(code) },
  }
}
