/**
 * `@eudikit/core/handler` — framework-agnostic WHATWG `Request` → `Response` handler.
 *
 * Routes it mounts ({base} = the verifier's `routeBasePath`):
 *
 *   POST {base}/requests                     → build a named request  { name, channel }
 *   POST {base}/verify                       → verify a DC API response { sessionId, response }
 *   GET  {base}/wallet/request/{id}.jwt      → request_uri (JAR; served once)
 *   POST {base}/wallet/response              → direct_post (response_uri)
 *   GET  {base}/sessions/{id}?response_code= → poll
 *
 * Surface control: `POST {base}/requests` exists only when a `requests` registry is
 * configured, clients may reference registered names only (never arbitrary DCQL), and each
 * name can restrict which channels it serves. Everything the browser reads is shaped here:
 * poll and verify responses carry `{ status, verified?, claims?, error? }`, with
 * `diagnostics` added only when `exposeDiagnostics` is opted into — check details are written
 * for operators, not for end-user screens. Rate limiting is deliberately left to the
 * application's middleware.
 */

import type {
  Channel,
  CreatedRequest,
  CreateRequestOptions,
  SessionStatus,
  VerificationResult,
  Verifier,
} from '../types.js'
import { EudikitError } from '../types.js'
import { verifierInternal } from '../verifier/create-verifier.js'

/**
 * One registry entry: request options minus the channel (the client picks that per call,
 * within the allowlist). Typed `CreateRequestOptions<unknown>` so presets with concrete claim
 * types (`presets.age()` and friends) register without casts.
 */
export type RegisteredRequest = Omit<CreateRequestOptions<unknown>, 'channel'> & {
  channels?: Channel[]
}

export interface FetchHandlerOptions {
  /**
   * Enables request creation over HTTP, so the React widget works with zero backend code.
   * Clients may only reference names registered here — arbitrary DCQL is NEVER accepted from a
   * client. Omit `channels` to allow every channel the profile matrix permits.
   */
  requests?: Record<string, RegisteredRequest>
  /** Include diagnostics in poll/verify responses? Default false. */
  exposeDiagnostics?: boolean
}

const JSON_HEADERS = { 'content-type': 'application/json' }

const SESSION_SEGMENT = /^[A-Za-z0-9_-]+$/

export function createFetchHandler(
  verifier: Verifier,
  options?: FetchHandlerOptions
): (request: Request) => Promise<Response> {
  const internal = verifierInternal(verifier)
  if (internal === null) {
    throw new EudikitError(
      'CONFIG_INVALID',
      'createFetchHandler needs a verifier created by createVerifier() — it reads the ' +
        'resolved routeBasePath from it'
    )
  }
  const base = internal.routeBasePath
  const exposeDiagnostics = options?.exposeDiagnostics === true

  return async (request: Request): Promise<Response> => {
    let pathname: string
    try {
      pathname = new URL(request.url).pathname
    } catch {
      return jsonError(404, 'not_found')
    }
    if (base !== '' && !(pathname === base || pathname.startsWith(`${base}/`))) {
      return jsonError(404, 'not_found')
    }
    const route = pathname.slice(base.length)

    if (route === '/requests') {
      if (request.method !== 'POST') return methodNotAllowed('POST')
      return handleCreateRequest(verifier, options?.requests, request)
    }

    if (route === '/verify') {
      if (request.method !== 'POST') return methodNotAllowed('POST')
      return handleVerify(verifier, request, exposeDiagnostics)
    }

    const requestUriMatch = /^\/wallet\/request\/([A-Za-z0-9_-]+)\.jwt$/.exec(route)
    if (requestUriMatch !== null) {
      if (request.method !== 'GET') return methodNotAllowed('GET')
      return verifier.handleRequestUri(request, requestUriMatch[1] as string)
    }

    if (route === '/wallet/response') {
      if (request.method !== 'POST') return methodNotAllowed('POST')
      return verifier.handleWalletResponse(request)
    }

    const sessionMatch = /^\/sessions\/([^/]+)$/.exec(route)
    if (sessionMatch !== null) {
      if (request.method !== 'GET') return methodNotAllowed('GET')
      return handlePoll(verifier, request, sessionMatch[1] as string, exposeDiagnostics)
    }

    return jsonError(404, 'not_found')
  }
}

// ---------------------------------------------------------------------------
// POST {base}/requests
// ---------------------------------------------------------------------------

async function handleCreateRequest(
  verifier: Verifier,
  registry: FetchHandlerOptions['requests'],
  request: Request
): Promise<Response> {
  // No registry, no surface: the route 404s exactly like an unknown path.
  if (registry === undefined) return jsonError(404, 'not_found')

  const body = await readJson(request)
  if (body === null) return jsonError(400, 'invalid_request')
  const name = body.name
  const channel = body.channel
  if (typeof name !== 'string' || typeof channel !== 'string') {
    return jsonError(400, 'invalid_request')
  }

  if (!Object.hasOwn(registry, name)) return jsonError(404, 'unknown_request')
  const entry = registry[name] as RegisteredRequest
  const { channels, ...createOptions } = entry
  if (channels !== undefined && !channels.includes(channel as Channel)) {
    return jsonError(400, 'channel_not_allowed')
  }

  try {
    const created = await verifier.requests.create<unknown>({
      ...createOptions,
      channel: channel as Channel,
    })
    return json(200, serializeCreatedRequest(created))
  } catch (error) {
    return errorResponse(error)
  }
}

/** `Date` → ISO string; everything else in a `CreatedRequest` is already JSON-shaped. */
function serializeCreatedRequest(created: CreatedRequest): Record<string, unknown> {
  return { ...created, expiresAt: created.expiresAt.toISOString() }
}

// ---------------------------------------------------------------------------
// POST {base}/verify + GET {base}/sessions/{id}
// ---------------------------------------------------------------------------

async function handleVerify(
  verifier: Verifier,
  request: Request,
  exposeDiagnostics: boolean
): Promise<Response> {
  const body = await readJson(request)
  if (body === null) return jsonError(400, 'invalid_request')
  const sessionId = body.sessionId
  const response = body.response
  if (typeof sessionId !== 'string' || typeof response !== 'object' || response === null) {
    return jsonError(400, 'invalid_request')
  }

  try {
    const result = await verifier.verify({
      sessionId,
      response: response as { protocol: string; data: unknown },
    })
    return json(200, resultBody(result, exposeDiagnostics))
  } catch (error) {
    return errorResponse(error)
  }
}

async function handlePoll(
  verifier: Verifier,
  request: Request,
  sessionId: string,
  exposeDiagnostics: boolean
): Promise<Response> {
  if (!SESSION_SEGMENT.test(sessionId)) return jsonError(404, 'not_found')
  const responseCode = new URL(request.url).searchParams.get('response_code')

  let status: SessionStatus
  try {
    status = await verifier.getResult(sessionId, {
      ...(responseCode !== null ? { responseCode } : {}),
    })
  } catch (error) {
    return errorResponse(error)
  }

  switch (status.status) {
    case 'pending':
      return json(200, { status: 'pending' })
    case 'expired':
      return json(200, { status: 'expired' })
    default:
      return json(200, resultBody(status.result, exposeDiagnostics))
  }
}

/**
 * The browser-facing result shape — poll and verify answer identically. Diagnostics stay
 * server-side unless explicitly exposed.
 */
function resultBody(
  result: VerificationResult,
  exposeDiagnostics: boolean
): Record<string, unknown> {
  return {
    status: result.verified ? 'verified' : 'failed',
    verified: result.verified,
    ...(result.verified ? { claims: result.claims } : {}),
    ...(result.error !== null
      ? {
          error: {
            code: result.error.code,
            message: result.error.message,
            ...(result.error.walletError !== undefined
              ? { walletError: result.error.walletError }
              : {}),
          },
        }
      : {}),
    ...(exposeDiagnostics ? { diagnostics: result.diagnostics } : {}),
  }
}

// ---------------------------------------------------------------------------
// low-level entry point for non-WHATWG frameworks (Express and friends)
// ---------------------------------------------------------------------------

export async function processWalletResponse(
  verifier: Verifier,
  form: URLSearchParams | Record<string, string>
): Promise<{ status: number; body: Record<string, unknown> }> {
  const params = form instanceof URLSearchParams ? form : new URLSearchParams(form)
  const response = await verifier.handleWalletResponse(
    new Request('http://handler.internal/wallet/response', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    })
  )
  return { status: response.status, body: (await response.json()) as Record<string, unknown> }
}

// ---------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------

async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const parsed = (await request.json()) as unknown
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null
    return parsed as Record<string, unknown>
  } catch {
    return null
  }
}

/**
 * Errors cross the HTTP boundary as bare stable codes. Messages stay server-side: they are
 * written for operators (they name env vars, config keys and URLs) and this is a public
 * endpoint.
 */
function errorResponse(error: unknown): Response {
  if (error instanceof EudikitError) {
    switch (error.code) {
      case 'SESSION_NOT_FOUND':
        return jsonError(404, error.code)
      case 'SESSION_ALREADY_CONSUMED':
        return jsonError(409, error.code)
      case 'RESPONSE_CODE_MISMATCH':
        return jsonError(403, error.code)
      default:
        return error.category === 'config' || error.category === 'wallet'
          ? jsonError(400, error.code)
          : jsonError(500, 'INTERNAL')
    }
  }
  return jsonError(500, 'INTERNAL')
}

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS })
}

function jsonError(status: number, code: string): Response {
  return json(status, { error: code })
}

function methodNotAllowed(allow: string): Response {
  return new Response(JSON.stringify({ error: 'method_not_allowed' }), {
    status: 405,
    headers: { ...JSON_HEADERS, allow },
  })
}
