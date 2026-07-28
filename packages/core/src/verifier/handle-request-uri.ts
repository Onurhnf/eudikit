/**
 * The `request_uri` endpoint: `GET {base}/wallet/request/{sessionId}.jwt` serves the signed
 * Request Object exactly once.
 *
 * Single use is built on the session adapter's atomic `consume`: the record is taken out of
 * the store, marked served and written back with its remaining TTL. Of two concurrent GETs,
 * exactly one obtains the record; the loser — like every later request — gets a `404` whose
 * body carries nothing, because an endpoint that distinguishes "never existed", "already
 * served" and "expired" is an oracle for probing session ids. The wallet that legitimately
 * fetched the JAR completes the flow through `direct_post`, which needs the restored record.
 *
 * The wallet-facing contract (OpenID4VP 1.0 §5.10): `200` with
 * `Content-Type: application/oauth-authz-req+jwt`, body = the JWS compact serialization. Any
 * HTTP error makes the wallet terminate the flow — which is exactly what a replayed or
 * expired request deserves.
 *
 * The endpoint is GET-only, and the requests this SDK produces never advertise
 * `request_uri_method` — absent means GET per OpenID4VP 1.0; POST negotiation
 * (`wallet_metadata`/`wallet_nonce`) is planned for a later release.
 */

import type { ResolvedVerifierConfig } from './config.js'
import { parsePendingRequestRecord, REQUEST_KEY_PREFIX } from './create-request.js'

const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]+$/

const JAR_CONTENT_TYPE = 'application/oauth-authz-req+jwt'

function notFound(): Response {
  return new Response(null, { status: 404 })
}

export async function handleRequestUri(
  config: ResolvedVerifierConfig,
  request: Request,
  sessionId: string
): Promise<Response> {
  if (request.method !== 'GET') {
    return new Response(null, { status: 405, headers: { allow: 'GET' } })
  }
  if (typeof sessionId !== 'string' || !SESSION_ID_PATTERN.test(sessionId)) {
    return notFound()
  }

  const stored = await config.session.consume(`${REQUEST_KEY_PREFIX}${sessionId}`)
  if (stored === null) return notFound()

  const record = parsePendingRequestRecord(stored)
  if (record === null) return notFound()

  const remainingSeconds = remainingTtlSeconds(record.expiresAt, config.now())
  if (record.jar === undefined || remainingSeconds <= 0) {
    // Not a by-reference session (or already past its lifetime): put the record back for the
    // response endpoint and reveal nothing.
    if (remainingSeconds > 0) {
      await config.session.set(`${REQUEST_KEY_PREFIX}${sessionId}`, record, remainingSeconds)
    }
    return notFound()
  }

  if (record.jarServed === true) {
    await config.session.set(`${REQUEST_KEY_PREFIX}${sessionId}`, record, remainingSeconds)
    return notFound()
  }

  await config.session.set(
    `${REQUEST_KEY_PREFIX}${sessionId}`,
    { ...record, jarServed: true },
    remainingSeconds
  )
  return new Response(record.jar, {
    status: 200,
    headers: { 'content-type': JAR_CONTENT_TYPE, 'cache-control': 'no-store' },
  })
}

function remainingTtlSeconds(expiresAt: string | undefined, now: Date): number {
  if (expiresAt === undefined) return 0
  const expiry = Date.parse(expiresAt)
  if (Number.isNaN(expiry)) return 0
  return Math.ceil((expiry - now.getTime()) / 1000)
}
