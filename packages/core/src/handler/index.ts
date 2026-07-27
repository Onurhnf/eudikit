/**
 * `@eudikit/core/handler` — framework-agnostic WHATWG `Request` → `Response` handler.
 *
 * Routes it mounts ({base} = `routeBasePath`):
 *   POST {base}/requests                     → build a named request  { name, channel } → CreatedRequest
 *   POST {base}/verify                       → verify a DC API response { sessionId, response }
 *   GET  {base}/wallet/request/{id}.jwt      → request_uri (JAR; served once)
 *   POST {base}/wallet/response              → direct_post (response_uri)
 *   GET  {base}/sessions/{id}?response_code= → poll
 *
 * STATUS: skeleton — see `src/index.ts`.
 */

import { notImplemented } from '../internal/not-implemented.js'
import type { Channel, CreateRequestOptions, Verifier } from '../types.js'

export interface FetchHandlerOptions {
  /**
   * Enables request creation over HTTP, so the React widget works with zero backend code.
   * Clients may only reference names registered here — arbitrary DCQL is NEVER accepted from a
   * client. Rate limiting is deliberately left to the application's middleware.
   */
  requests?: Record<string, Omit<CreateRequestOptions, 'channel'> & { channels?: Channel[] }>
  /** Include diagnostics in the poll response? Default false — clients see only status/verified/claims. */
  exposeDiagnostics?: boolean
}

export function createFetchHandler(
  _verifier: Verifier,
  _options?: FetchHandlerOptions
): (request: Request) => Promise<Response> {
  return notImplemented('createFetchHandler()')
}

/** Low-level entry point for non-WHATWG frameworks (Express and friends). */
export function processWalletResponse(
  _verifier: Verifier,
  _form: URLSearchParams | Record<string, string>
): Promise<{ status: number; body: Record<string, unknown> }> {
  return notImplemented('processWalletResponse()')
}
