/**
 * The cross-device wait. A QR or deep-link request settles out of band — the wallet posts to
 * the server, not to this page — so the only way to learn the outcome is to ask the server
 * until it has one.
 *
 * The loop is deliberately un-eager: every pending answer stretches the next wait by half
 * again up to a ceiling, and a hidden tab does not poll at all — the runner parks itself
 * until `resume()`, which the hook wires to `visibilitychange`. Only transport failures are
 * retried, and only a few in a row. An HTTP verdict ends the loop at once; the client layer
 * explains why verdicts are never replayed.
 */

import {
  HandlerError,
  pollSession,
  type ResultBody,
  type SerializedCreatedRequest,
  toVerificationError,
} from './client.js'
import type {
  UseVerificationOptions,
  VerificationError,
  VerificationState,
} from './use-verification.js'

const DEFAULT_POLL_INTERVAL_MS = 1500
const MAX_POLL_INTERVAL_MS = 8000
const POLL_BACKOFF = 1.5
/** Consecutive transport failures tolerated before a poll gives up. */
const MAX_POLL_FAILURES = 4

export interface PollingStart {
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

export function beginPolling(start: PollingStart): void {
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

export interface PollRunner {
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
