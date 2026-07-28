/**
 * The HTTP client for the core handler's browser-facing routes.
 *
 * ```
 * POST {endpoint}/requests        { name, channel }              → a created request
 * POST {endpoint}/verify          { sessionId, response }        → a result
 * GET  {endpoint}/sessions/{id}                                  → pending | expired | a result
 * ```
 *
 * The handler answers errors as a bare stable code and keeps its messages server-side (they are
 * written for operators and name env vars and URLs). Turning those codes into something a person
 * can read is this layer's job, so nothing that reaches a screen was written for a log.
 *
 * Retries cover transport failures only — a fetch that never got an answer. An HTTP error is a
 * verdict and is never retried: replaying `/verify` against a consumed session would turn one
 * honest failure into a confusing `SESSION_ALREADY_CONSUMED`.
 */

import type { EudikitErrorCode } from '@eudikit/core'
import type { VerificationError } from './use-verification.js'

/** `CreatedRequest` as it crosses HTTP: identical, with `expiresAt` as an ISO string. */
export type SerializedCreatedRequest =
  | {
      channel: 'dc-api'
      sessionId: string
      dcApiRequest: { protocol: string; data: Record<string, unknown> }
      expiresAt: string
    }
  | { channel: 'qr'; sessionId: string; qrPayload: string; requestUri?: string; expiresAt: string }
  | {
      channel: 'deep-link'
      sessionId: string
      deepLink: string
      requestUri?: string
      expiresAt: string
    }

/** The shared shape of `/verify` and `/sessions/{id}` responses. */
export interface ResultBody {
  status: 'pending' | 'expired' | 'verified' | 'failed'
  verified?: boolean
  claims?: Record<string, unknown>
  error?: { code: EudikitErrorCode; message?: string; walletError?: string }
}

export class HandlerError extends Error {
  readonly code: EudikitErrorCode
  /** True when the request never reached the server; retrying later may work. */
  readonly network: boolean

  constructor(code: EudikitErrorCode, message: string, options?: { network?: boolean }) {
    super(message)
    this.name = 'HandlerError'
    this.code = code
    this.network = options?.network === true
  }
}

const DEFAULT_RETRIES = 2
const RETRY_BASE_MS = 250

export interface EndpointOptions {
  endpoint: string
  signal: AbortSignal
}

export async function createRequest(
  options: EndpointOptions & { name: string; channel: string }
): Promise<SerializedCreatedRequest> {
  const body = await fetchJson(`${trimEnd(options.endpoint)}/requests`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: options.name, channel: options.channel }),
    signal: options.signal,
  })
  const created = body as SerializedCreatedRequest
  if (typeof created?.sessionId !== 'string' || typeof created?.channel !== 'string') {
    throw new HandlerError(
      'INTERNAL',
      `${options.endpoint}/requests did not answer with a created request — is the eudikit ` +
        'handler mounted at this path?'
    )
  }
  return created
}

export async function submitDcApiResponse(
  options: EndpointOptions & { sessionId: string; response: { protocol: string; data: unknown } }
): Promise<ResultBody> {
  const body = await fetchJson(`${trimEnd(options.endpoint)}/verify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: options.sessionId, response: options.response }),
    signal: options.signal,
  })
  return asResultBody(body)
}

export async function pollSession(
  options: EndpointOptions & { sessionId: string }
): Promise<ResultBody> {
  const url = `${trimEnd(options.endpoint)}/sessions/${encodeURIComponent(options.sessionId)}`
  const body = await fetchJson(
    url,
    { method: 'GET', headers: { accept: 'application/json' }, signal: options.signal },
    // A poll runs on a loop that retries on its own schedule; retrying inside a tick as well
    // would only stack requests on a flaky link.
    0
  )
  return asResultBody(body)
}

// ---------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------

async function fetchJson(
  url: string,
  init: RequestInit,
  retries = DEFAULT_RETRIES
): Promise<unknown> {
  let attempt = 0
  for (;;) {
    let response: Response
    try {
      response = await fetch(url, init)
    } catch (cause) {
      if (init.signal?.aborted === true) throw cause
      if (attempt >= retries) {
        throw new HandlerError(
          'INTERNAL',
          `could not reach ${url} — check that the eudikit handler is mounted and reachable`,
          { network: true }
        )
      }
      attempt += 1
      await sleep(RETRY_BASE_MS * 2 ** (attempt - 1))
      continue
    }

    const body = await readJson(response)
    if (!response.ok) throw handlerError(response.status, body, url)
    return body
  }
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    return null
  }
}

/**
 * Maps the handler's route-level codes onto the public error taxonomy. Anything that is
 * already an `EudikitErrorCode` passes through unchanged; the lowercase route codes describe a
 * mounting or registry mistake, which is a configuration error on the integrator's side.
 */
const ROUTE_CODES: Record<string, EudikitErrorCode> = {
  channel_not_allowed: 'CHANNEL_PROFILE_MISMATCH',
  invalid_request: 'CONFIG_INVALID',
  method_not_allowed: 'CONFIG_INVALID',
  not_found: 'CONFIG_INVALID',
  unknown_request: 'CONFIG_INVALID',
}

const MESSAGES: Partial<Record<EudikitErrorCode, string>> = {
  CHANNEL_PROFILE_MISMATCH: 'this request does not serve the channel that was asked for',
  CONFIG_INVALID:
    'the eudikit handler rejected the call — check the endpoint path and that the request ' +
    'name is registered on the server',
  CONFIG_PUBLIC_BASE_URL_REQUIRED:
    'the server has no publicly reachable base URL, which the QR and deep-link channels need',
  SESSION_ALREADY_CONSUMED: 'this verification was already completed once',
  SESSION_NOT_FOUND: 'this verification is no longer available; start a new one',
  USER_DECLINED_OR_NO_CREDENTIAL: 'no matching credential was shared',
  WALLET_UNAVAILABLE: 'no wallet answered on this device',
}

function handlerError(status: number, body: unknown, url: string): HandlerError {
  const raw =
    typeof body === 'object' && body !== null ? (body as { error?: unknown }).error : undefined
  const code =
    typeof raw === 'string'
      ? (ROUTE_CODES[raw] ?? (raw as EudikitErrorCode))
      : ('INTERNAL' as EudikitErrorCode)
  return new HandlerError(
    code,
    MESSAGES[code] ?? `${url} answered ${status} (${String(raw ?? 'no error code')})`
  )
}

function asResultBody(body: unknown): ResultBody {
  if (typeof body !== 'object' || body === null) {
    throw new HandlerError('INTERNAL', 'the eudikit handler answered with an unreadable body')
  }
  const status = (body as { status?: unknown }).status
  if (
    status !== 'pending' &&
    status !== 'expired' &&
    status !== 'verified' &&
    status !== 'failed'
  ) {
    throw new HandlerError('INTERNAL', 'the eudikit handler answered with an unknown status')
  }
  return body as ResultBody
}

/** Human-readable text for a code that arrived without one. */
export function describeCode(code: EudikitErrorCode): string {
  return MESSAGES[code] ?? 'verification could not be completed'
}

/** Folds anything thrown around a request into the `{ code, message }` pair the hook reports. */
export function toVerificationError(cause: unknown): VerificationError {
  if (cause instanceof HandlerError) {
    return { code: cause.code, message: cause.message }
  }
  return {
    code: 'INTERNAL',
    message: cause instanceof Error ? cause.message : 'the verification could not be started',
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

function trimEnd(endpoint: string): string {
  return endpoint.endsWith('/') ? endpoint.slice(0, -1) : endpoint
}
