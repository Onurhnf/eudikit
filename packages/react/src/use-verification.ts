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
  HandlerError,
  pollSession,
  type ResultBody,
  type SerializedCreatedRequest,
  submitDcApiResponse,
} from './client.js'
import {
  classifyDcApiError,
  digitalCredentialsAvailable,
  requestDigitalCredential,
  userAgentAllowsAnyProtocol,
  userAgentAllowsProtocol,
} from './dc-api.js'

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
const DEFAULT_POLL_INTERVAL_MS = 1500
const MAX_POLL_INTERVAL_MS = 8000
const POLL_BACKOFF = 1.5
/** Consecutive transport failures tolerated before a poll gives up. */
const MAX_POLL_FAILURES = 4

interface VerificationState {
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
// channel runners
// ---------------------------------------------------------------------------

interface DcApiRun {
  created: Extract<SerializedCreatedRequest, { channel: 'dc-api' }>
  endpoint: string
  signal: AbortSignal
  isCurrent: () => boolean
  apply: (patch: Partial<VerificationState>) => void
  settle: (body: ResultBody) => void
  fail: (failure: VerificationError) => void
}

/**
 * The whole DC API round trip. `done` means the attempt reached a verdict (or was cancelled);
 * anything else hands back a reason and lets the caller try the next channel — that is the
 * progressive-enhancement path, and it must stay silent: the user has not been shown anything
 * about the DC API at this point.
 */
async function runDcApi(
  run: DcApiRun
): Promise<{ done: true } | { done: false; reason: VerificationError }> {
  const { protocol, data } = run.created.dcApiRequest
  if (!userAgentAllowsProtocol(protocol)) {
    return {
      done: false,
      reason: {
        code: 'UNSUPPORTED_PROTOCOL',
        message: `this browser does not accept the ${protocol} protocol`,
      },
    }
  }

  run.apply({
    status: 'awaiting_wallet',
    channel: 'dc-api',
    sessionId: run.created.sessionId,
    qrPayload: null,
    deepLink: null,
  })

  let response: { protocol: string; data: unknown }
  try {
    response = await requestDigitalCredential({ protocol, data }, run.signal)
  } catch (cause) {
    if (!run.isCurrent()) return { done: true }
    const failure = classifyDcApiError(cause)
    if (failure.aborted) return { done: true }
    if (failure.fallback) {
      return { done: false, reason: { code: failure.code, message: failure.message } }
    }
    run.fail({ code: failure.code, message: failure.message })
    return { done: true }
  }
  if (!run.isCurrent()) return { done: true }

  let body: ResultBody
  try {
    body = await submitDcApiResponse({
      endpoint: run.endpoint,
      sessionId: run.created.sessionId,
      response,
      signal: run.signal,
    })
  } catch (cause) {
    if (!run.isCurrent()) return { done: true }
    run.fail(toVerificationError(cause))
    return { done: true }
  }
  if (!run.isCurrent()) return { done: true }

  // The wallet was never invoked: the request did not reach a wallet at all, so the
  // cross-device channel is the honest next attempt rather than a failure to report.
  if (body.status === 'failed' && body.error?.code === 'WALLET_UNAVAILABLE') {
    return {
      done: false,
      reason: { code: 'WALLET_UNAVAILABLE', message: describeCode('WALLET_UNAVAILABLE') },
    }
  }

  run.settle(body)
  return { done: true }
}

interface PollingStart {
  created: Extract<SerializedCreatedRequest, { channel: 'qr' | 'deep-link' }>
  settings: UseVerificationOptions
  controller: AbortController
  run: number
  isCurrent: () => boolean
  apply: (patch: Partial<VerificationState>) => void
  settle: (body: ResultBody) => void
  fail: (failure: VerificationError) => void
  pollRef: { current: PollRunner | null }
}

function beginPolling(start: PollingStart): void {
  const { created } = start
  start.apply({
    status: 'polling',
    channel: created.channel,
    sessionId: created.sessionId,
    qrPayload: created.channel === 'qr' ? created.qrPayload : null,
    deepLink: created.channel === 'deep-link' ? created.deepLink : null,
  })

  const expiresAt = Date.parse(created.expiresAt)
  const runner = createPollRunner({
    endpoint: start.settings.endpoint,
    sessionId: created.sessionId,
    expiresAt: Number.isNaN(expiresAt) ? Number.POSITIVE_INFINITY : expiresAt,
    intervalMs: start.settings.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
    signal: start.controller.signal,
    isCurrent: start.isCurrent,
    onResult: start.settle,
    onExpired: () => {
      start.apply({ status: 'expired' })
    },
    onError: start.fail,
  })
  start.pollRef.current = runner
  runner.resume()
}

// ---------------------------------------------------------------------------
// polling
// ---------------------------------------------------------------------------

interface PollRunner {
  /** Starts the loop, or picks it up again after the tab was hidden. */
  resume(): void
  stop(): void
}

interface PollContext {
  endpoint: string
  sessionId: string
  expiresAt: number
  intervalMs: number
  signal: AbortSignal
  isCurrent: () => boolean
  onResult: (body: ResultBody) => void
  onExpired: () => void
  onError: (failure: VerificationError) => void
}

function createPollRunner(context: PollContext): PollRunner {
  let timer: ReturnType<typeof setTimeout> | null = null
  let paused = false
  let stopped = false
  let attempt = 0
  let failures = 0

  const schedule = (): void => {
    if (stopped || timer !== null) return
    const delay = Math.min(context.intervalMs * POLL_BACKOFF ** attempt, MAX_POLL_INTERVAL_MS)
    timer = setTimeout(() => {
      timer = null
      void tick()
    }, delay)
  }

  const hidden = (): boolean =>
    typeof document !== 'undefined' && document.visibilityState === 'hidden'

  const tick = async (): Promise<void> => {
    if (stopped || !context.isCurrent()) return
    if (hidden()) {
      paused = true
      return
    }
    if (Date.now() >= context.expiresAt) {
      stopped = true
      context.onExpired()
      return
    }

    try {
      const body = await pollSession({
        endpoint: context.endpoint,
        sessionId: context.sessionId,
        signal: context.signal,
      })
      if (stopped || !context.isCurrent()) return
      failures = 0
      if (body.status === 'pending') {
        attempt += 1
        schedule()
        return
      }
      stopped = true
      context.onResult(body)
    } catch (cause) {
      if (stopped || !context.isCurrent() || context.signal.aborted) return
      const retryable = cause instanceof HandlerError && cause.network
      failures += 1
      if (!retryable || failures > MAX_POLL_FAILURES) {
        stopped = true
        context.onError(toVerificationError(cause))
        return
      }
      attempt += 1
      schedule()
    }
  }

  return {
    resume() {
      if (stopped) return
      if (paused) {
        // Coming back to the tab deserves a prompt answer, not the tail of a long backoff.
        paused = false
        attempt = 0
      }
      schedule()
    },
    stop() {
      stopped = true
      if (timer !== null) {
        clearTimeout(timer)
        timer = null
      }
    },
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

function dcApiUsable(): boolean {
  return digitalCredentialsAvailable() && userAgentAllowsAnyProtocol()
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

function toVerificationError(cause: unknown): VerificationError {
  if (cause instanceof HandlerError) {
    return { code: cause.code, message: cause.message }
  }
  return {
    code: 'INTERNAL',
    message: cause instanceof Error ? cause.message : 'the verification could not be started',
  }
}
