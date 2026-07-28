/**
 * The DC API channel: whether this browser can attempt it at all, and the whole round trip —
 * `navigator.credentials.get()` with the created request, then its response posted to the
 * server for verification.
 *
 * The transient-activation rule shapes this module the same way it shapes the hook: nothing
 * here waits on a timer, so the browser call stays inside the promise chain of the click
 * handler that started it.
 */

import {
  describeCode,
  type ResultBody,
  type SerializedCreatedRequest,
  submitDcApiResponse,
  toVerificationError,
} from './client.js'
import {
  classifyDcApiError,
  digitalCredentialsAvailable,
  requestDigitalCredential,
  userAgentAllowsAnyProtocol,
  userAgentAllowsProtocol,
} from './dc-api.js'
import type { VerificationError, VerificationState } from './use-verification.js'

/** True when this browser can attempt the DC API with a protocol this release emits. */
export function dcApiUsable(): boolean {
  return digitalCredentialsAvailable() && userAgentAllowsAnyProtocol()
}

export interface DcApiRun {
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
export async function runDcApi(
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
