/**
 * The Digital Credentials API browser layer: feature detection, protocol negotiation, the
 * `navigator.credentials.get()` call itself, and the mapping from browser failures onto the
 * SDK's error codes.
 *
 * Everything here is deliberately defensive. The API is young, the shape of a rejection differs
 * between engines, and two of its rules are easy to trip over:
 *
 *  - `DigitalCredential` may be undefined, in which case even *reading*
 *    `DigitalCredential.userAgentAllowsProtocol` throws — hence the `typeof` guard.
 *  - `get()` consumes transient activation, so it MUST be reached from the click handler's own
 *    promise chain. Nothing in this module schedules work on a timer.
 *
 * A wallet-side protocol error does NOT reject: the promise fulfils with
 * `data = { error: '<code>' }`. That path is left to the server — the response is posted to the
 * verifier like any other, so the session is consumed and the outcome recorded exactly once.
 */

import type { EudikitErrorCode } from '@eudikit/core'

/** The protocols this release can produce, most specific first. */
export const DC_API_PROTOCOLS = ['openid4vp-v1-signed', 'openid4vp-v1-unsigned'] as const

export interface DcApiRequest {
  protocol: string
  data: Record<string, unknown>
}

/** The serialized `DigitalCredential`, exactly as the server's `/verify` route expects it. */
export interface DcApiResponse {
  protocol: string
  data: unknown
}

export interface DcApiFailure {
  code: EudikitErrorCode
  message: string
  /** Whether the flow should quietly continue on the next channel (QR). */
  fallback: boolean
  /** True when the call ended because `cancel()` aborted it — not an error to report. */
  aborted: boolean
}

interface DigitalCredentialStatic {
  userAgentAllowsProtocol?: (protocol: string) => boolean
}

interface DigitalCredentialsContainer {
  get(options: {
    digital: { requests: Array<{ protocol: string; data: unknown }> }
    signal?: AbortSignal
  }): Promise<{ protocol: string; data: unknown } | null>
}

function digitalCredentialStatic(): DigitalCredentialStatic | undefined {
  if (typeof globalThis === 'undefined') return undefined
  const candidate = (globalThis as unknown as Record<string, unknown>).DigitalCredential
  return typeof candidate === 'function'
    ? (candidate as unknown as DigitalCredentialStatic)
    : undefined
}

/** True when this document can even attempt a DC API call. Safe to call during SSR. */
export function digitalCredentialsAvailable(): boolean {
  if (digitalCredentialStatic() === undefined) return false
  return (
    typeof navigator !== 'undefined' &&
    typeof (navigator as { credentials?: { get?: unknown } }).credentials?.get === 'function'
  )
}

/**
 * Protocol negotiation. `userAgentAllowsProtocol` returns false for unknown protocols rather
 * than throwing, but it is itself a recent addition: a browser that ships `DigitalCredential`
 * without it gets the benefit of the doubt, and an unsupported protocol surfaces as the
 * `TypeError` the spec mandates for an empty validated-request list — which falls back to QR
 * just the same.
 */
export function userAgentAllowsProtocol(protocol: string): boolean {
  const dc = digitalCredentialStatic()
  if (dc === undefined) return false
  if (typeof dc.userAgentAllowsProtocol !== 'function') return true
  try {
    return dc.userAgentAllowsProtocol(protocol) === true
  } catch {
    return false
  }
}

/** Whether any protocol this release emits is accepted by the user agent. */
export function userAgentAllowsAnyProtocol(): boolean {
  return DC_API_PROTOCOLS.some(userAgentAllowsProtocol)
}

/**
 * MUST be awaited directly from the `start()` chain: every tick spent elsewhere brings the
 * transient activation window closer to expiry.
 */
export async function requestDigitalCredential(
  request: DcApiRequest,
  signal: AbortSignal
): Promise<DcApiResponse> {
  const container = (navigator as unknown as { credentials: DigitalCredentialsContainer })
    .credentials
  const credential = await container.get({
    digital: { requests: [{ protocol: request.protocol, data: request.data }] },
    signal,
  })
  if (credential === null) {
    throw new DcApiEmptyResponse()
  }
  return { protocol: credential.protocol, data: credential.data }
}

/** `get()` resolving to null is not in the spec's happy path, so it gets a name of its own. */
class DcApiEmptyResponse extends Error {
  constructor() {
    super('the Digital Credentials API returned no credential')
    this.name = 'DcApiEmptyResponse'
  }
}

/**
 * Browser failure → SDK error code.
 *
 * `NotAllowedError` is the collecting bucket the spec chose: the user declined, no wallet held
 * a matching credential, the call had no transient activation, or the document was not the one
 * with user attention. It maps onto the equally combined `USER_DECLINED_OR_NO_CREDENTIAL`, and
 * does not fall back to QR — the user was asked, and answering by silently swapping the UI
 * underneath them is worse than saying what happened.
 */
export function classifyDcApiError(error: unknown): DcApiFailure {
  const name = error instanceof Error ? error.name : ''

  if (name === 'AbortError') {
    return {
      code: 'INTERNAL',
      message: 'the credential request was aborted',
      fallback: false,
      aborted: true,
    }
  }

  if (name === 'NotAllowedError') {
    return {
      code: 'USER_DECLINED_OR_NO_CREDENTIAL',
      message:
        'no credential was shared: the request was declined, no wallet held a matching ' +
        'credential, or the browser refused the call (it must run in a click handler, in the ' +
        'foreground tab)',
      fallback: false,
      aborted: false,
    }
  }

  if (name === 'SecurityError') {
    return {
      code: 'INTERNAL',
      message:
        'the browser refused the credential request for this document (an insecure context ' +
        'or a sandboxed frame)',
      fallback: true,
      aborted: false,
    }
  }

  if (name === 'TypeError' || name === 'NotSupportedError' || name === 'InvalidStateError') {
    return {
      code: 'UNSUPPORTED_PROTOCOL',
      message: 'this browser does not support the requested credential protocol',
      fallback: true,
      aborted: false,
    }
  }

  return {
    code: 'INTERNAL',
    message: error instanceof Error ? error.message : 'the credential request failed',
    fallback: true,
    aborted: false,
  }
}
