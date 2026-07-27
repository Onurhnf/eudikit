/**
 * The `direct_post` response endpoint (OpenID4VP 1.0 §8.2) as a WHATWG `Request` → `Response`
 * function — where the wallet's form POST lands in the QR and deep-link flows.
 *
 * Contract highlights, all pinned by tests:
 *
 *  - Only `POST` with `application/x-www-form-urlencoded` is accepted. Error responses to the
 *    wallet never say which part of the request was wrong: a missing `state`, an unknown
 *    `state` and a replayed `state` all produce the same `400 {"error":"invalid_request"}`,
 *    because a response endpoint that explains its failures is an oracle for probing sessions.
 *  - The session is consumed **atomically** before anything else happens; the second POST for
 *    the same `state` finds nothing and gets the 400 above. This is the replay defense.
 *  - A wallet error (`error=access_denied…`) is a *successful* protocol exchange: the result is
 *    recorded as failed and the wallet still receives `200 {}`.
 *  - The verification chain runs to completion and the result is stored **before** the HTTP
 *    response is produced, so a `200` to the wallet implies the outcome is already pollable.
 *  - In redirect mode the 200 carries `{"redirect_uri"}` with a fresh ≥128-bit `response_code`
 *    substituted into the configured template; the code is stored with the result and checked
 *    by `getResult` (OpenID4VP 1.0 §14.3.3).
 *
 * The iOS AV wallet serializes the token map as `vp_token[queryId]=…` form fields instead of a
 * single JSON `vp_token` field; both spellings are parsed.
 */

import { randomBytes } from 'node:crypto'
import { buildOpenID4VPSessionTranscript } from '../mdoc/session-transcript.js'
import type { Check, EudikitErrorCode, VerificationResult } from '../types.js'
import { EudikitError } from '../types.js'
import { runVerification } from '../verify/engine.js'
import { RESULT_KEY_PREFIX, toResultRecord } from '../verify/result-record.js'
import type { ResolvedVerifierConfig } from './config.js'
import {
  type PendingRequestRecord,
  parsePendingRequestRecord,
  REQUEST_KEY_PREFIX,
  RESPONSE_CODE_PLACEHOLDER,
} from './create-request.js'
import type { PresetRegistry } from './preset-registry.js'

const FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded'
const RESPONSE_CODE_BYTES = 32

const JSON_HEADERS = { 'content-type': 'application/json' }

function invalidRequest(status: number): Response {
  return new Response(JSON.stringify({ error: 'invalid_request' }), {
    status,
    headers: JSON_HEADERS,
  })
}

export async function handleWalletResponse(
  config: ResolvedVerifierConfig,
  presets: PresetRegistry,
  request: Request
): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'invalid_request' }), {
      status: 405,
      headers: { ...JSON_HEADERS, allow: 'POST' },
    })
  }
  const contentType = request.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().startsWith(FORM_CONTENT_TYPE)) {
    return invalidRequest(400)
  }

  let form: URLSearchParams
  try {
    form = new URLSearchParams(await request.text())
  } catch {
    return invalidRequest(400)
  }

  const state = form.get('state')
  if (state === null || state === '') return invalidRequest(400)

  // Atomic single-use consumption: of two concurrent POSTs for the same state, exactly one
  // proceeds past this line.
  const stored = await config.session.consume(`${REQUEST_KEY_PREFIX}${state}`)
  if (stored === null) return invalidRequest(400)

  const record = parsePendingRequestRecord(stored)
  if (record === null || record.state !== state || record.responseUri === undefined) {
    // A dc-api session id posted to the direct_post endpoint, or a record from a future
    // version: not a session this endpoint can complete.
    return invalidRequest(400)
  }

  const baseChecks = sessionChecks(record)

  const walletError = form.get('error')
  if (walletError !== null) {
    const result = failedResult(config, record, state, baseChecks, {
      code: mapWalletError(walletError),
      message:
        form.get('error_description') === null
          ? `the wallet returned "${walletError}"`
          : `the wallet returned "${walletError}": ${form.get('error_description')}`,
      walletError,
    })
    await storeResult(config, state, result)
    return new Response(JSON.stringify({}), { status: 200, headers: JSON_HEADERS })
  }

  const vpToken = parseVpToken(form)
  let result: VerificationResult
  if (vpToken === null) {
    result = failedResult(config, record, state, baseChecks, {
      code: 'PRESENTATION_MALFORMED',
      message: 'the response carries neither a parseable vp_token nor an error field',
    })
  } else {
    result = await verifyResponse(config, presets, record, state, vpToken, baseChecks)
  }

  // Store first, respond second: a 200 to the wallet is the promise that the outcome is
  // already pollable.
  const responseCode =
    record.successRedirectTemplate !== undefined
      ? randomBytes(RESPONSE_CODE_BYTES).toString('base64url')
      : undefined
  await storeResult(config, state, result, responseCode)

  if (record.successRedirectTemplate !== undefined && responseCode !== undefined) {
    const redirectUri = record.successRedirectTemplate.replace(
      RESPONSE_CODE_PLACEHOLDER,
      responseCode
    )
    return new Response(JSON.stringify({ redirect_uri: redirectUri }), {
      status: 200,
      headers: JSON_HEADERS,
    })
  }
  return new Response(JSON.stringify({}), { status: 200, headers: JSON_HEADERS })
}

// ---------------------------------------------------------------------------
// verification path
// ---------------------------------------------------------------------------

async function verifyResponse(
  config: ResolvedVerifierConfig,
  presets: PresetRegistry,
  record: PendingRequestRecord,
  state: string,
  vpToken: Record<string, string[]>,
  baseChecks: Check[]
): Promise<VerificationResult> {
  // The wallet signed the SessionTranscript over the values of the authorization request;
  // rebuilding it from the session record is what binds this response to that exact request
  // (nonce binding lives here). The `av` flow is unencrypted, so jwkThumbprint is null.
  const responseUri = record.responseUri as string
  const sessionTranscript = buildOpenID4VPSessionTranscript({
    clientId: `redirect_uri:${responseUri}`,
    nonce: record.nonce,
    jwkThumbprint: null,
    responseUri,
  })

  const preset = record.presetId !== undefined ? presets.get(record.presetId) : undefined
  return runVerification({
    vpToken,
    dcql: record.dcql,
    sessionTranscript,
    trust: config.trust,
    profile: record.profile,
    sessionId: state,
    now: config.now(),
    baseChecks,
    ...(preset !== undefined ? { preset } : {}),
  })
}

/**
 * Session-class checks for a consumed direct_post record. They read as all-passed by
 * construction — a session that failed them never reaches result production — and are listed
 * anyway because every result carries the full report.
 */
function sessionChecks(record: PendingRequestRecord): Check[] {
  return [
    { id: 'session.found', status: 'passed', detail: 'state resolved to a pending request' },
    {
      id: 'session.single_use',
      status: 'passed',
      detail: 'the pending request was consumed atomically; a replay finds nothing',
    },
    {
      id: 'session.not_expired',
      status: 'passed',
      detail: 'the record was still live in the session store (TTL not reached)',
    },
    { id: 'session.state_match', status: 'passed', detail: 'form state equals the stored state' },
    {
      id: 'session.response_mode_match',
      status: 'passed',
      detail: `the ${record.channel} channel expects a direct_post form response`,
    },
    {
      id: 'session.origin_allowed',
      status: 'skipped',
      detail:
        'browser-attested origins exist only on the Digital Credentials API channel; the ' +
        'direct_post binding is nonce + state + response_uri',
    },
    {
      id: 'envelope.jwe_decrypted',
      status: 'skipped',
      detail: 'the av profile mandates unencrypted direct_post (no JWE envelope)',
    },
    {
      id: 'envelope.key_binding',
      status: 'skipped',
      detail: 'no response encryption key on an unencrypted flow',
    },
  ]
}

// ---------------------------------------------------------------------------
// vp_token parsing (standard JSON field + iOS bracket fields)
// ---------------------------------------------------------------------------

function parseVpToken(form: URLSearchParams): Record<string, string[]> | null {
  const out: Record<string, string[]> = {}

  const raw = form.get('vp_token')
  if (raw !== null) {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      return null
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null
    for (const [queryId, value] of Object.entries(parsed)) {
      const presentations = asPresentationList(value)
      if (presentations === null) return null
      out[queryId] = presentations
    }
  }

  // iOS AV wallet spelling: one `vp_token[queryId]` form field per credential query.
  for (const [key, value] of form.entries()) {
    const match = /^vp_token\[(.+)\]$/.exec(key)
    if (match === null) continue
    const queryId = match[1] as string
    const existing = out[queryId] ?? []
    existing.push(value)
    out[queryId] = existing
  }

  return Object.keys(out).length > 0 ? out : null
}

/** The spec value is an array of presentations; a bare string is tolerated as a one-element list. */
function asPresentationList(value: unknown): string[] | null {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value) && value.every((entry) => typeof entry === 'string')) {
    return value as string[]
  }
  return null
}

// ---------------------------------------------------------------------------
// failure results
// ---------------------------------------------------------------------------

/**
 * OpenID4VP §8.5 error → our taxonomy. `access_denied` deliberately collapses "no matching
 * credential", "no consent" and "could not authenticate" (the spec merges them and wallets are
 * encouraged to stay silent); the `invalid_*` family means the wallet rejected *our* request.
 */
function mapWalletError(code: string): EudikitErrorCode {
  switch (code) {
    case 'access_denied':
      return 'USER_DECLINED_OR_NO_CREDENTIAL'
    case 'vp_formats_not_supported':
      return 'WALLET_FORMAT_UNSUPPORTED'
    case 'wallet_unavailable':
      return 'WALLET_UNAVAILABLE'
    default:
      // invalid_request / invalid_client / invalid_scope, and any code this release does not
      // know: the raw wallet code is preserved on the error either way.
      return 'WALLET_REJECTED_REQUEST'
  }
}

/** A failed result produced without running the verification chain (wallet error / no token). */
function failedResult(
  config: ResolvedVerifierConfig,
  record: PendingRequestRecord,
  state: string,
  baseChecks: Check[],
  failure: { code: EudikitErrorCode; message: string; walletError?: string }
): VerificationResult {
  return {
    verified: false,
    profile: record.profile,
    policy: config.trust.mode,
    claims: null,
    credentials: [],
    diagnostics: baseChecks,
    error: new EudikitError(failure.code, failure.message, {
      ...(failure.walletError !== undefined ? { walletError: failure.walletError } : {}),
    }),
    sessionId: state,
  }
}

async function storeResult(
  config: ResolvedVerifierConfig,
  sessionId: string,
  result: VerificationResult,
  responseCode?: string
): Promise<void> {
  await config.session.set(
    `${RESULT_KEY_PREFIX}${sessionId}`,
    toResultRecord(result, responseCode),
    config.resultTtlSeconds
  )
}
