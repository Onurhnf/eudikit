/**
 * The `direct_post` / `direct_post.jwt` response endpoint (OpenID4VP 1.0 §8.2) as a WHATWG
 * `Request` → `Response` function — where the wallet's POST lands in the QR and deep-link
 * flows.
 *
 * Contract highlights, all pinned by tests:
 *
 *  - Only `POST` with `application/x-www-form-urlencoded` is accepted. Error responses to the
 *    wallet never say which part of the request was wrong: a missing `state`, an unknown
 *    `state`, an unroutable JWE and a replayed session all produce the same
 *    `400 {"error":"invalid_request"}`, because a response endpoint that explains its
 *    failures is an oracle for probing sessions.
 *  - The session is consumed **atomically** before anything else happens; the second POST for
 *    the same session finds nothing and gets the 400 above. This is the replay defense.
 *  - `direct_post.jwt` arrives as a single `response` field (a JWE) with no clear-text
 *    `state`; the session is found through the JWE header's `kid`, which names the ephemeral
 *    key — and therefore the request — the response was encrypted to. The `state` inside the
 *    decrypted payload is then checked against the stored one. A wallet MAY send its *error*
 *    response unencrypted even on an encrypted flow, and that is tolerated; an unencrypted
 *    `vp_token` on an encrypted flow is not.
 *  - A wallet error (`error=access_denied…`) is a *successful* protocol exchange: the result
 *    is recorded as failed and the wallet still receives `200 {}`.
 *  - The verification chain runs to completion and the result is stored **before** the HTTP
 *    response is produced, so a `200` to the wallet implies the outcome is already pollable.
 *  - In redirect mode the 200 carries `{"redirect_uri"}` with a fresh ≥128-bit
 *    `response_code` substituted into the configured template; the code is stored with the
 *    result and checked by `getResult` (OpenID4VP 1.0 §14.3.3).
 *
 * The iOS AV wallet serializes the token map as `vp_token[queryId]=…` form fields instead of
 * a single JSON `vp_token` field; both spellings are parsed.
 */

import { randomBytes } from 'node:crypto'
import { buildOpenID4VPSessionTranscript } from '../mdoc/session-transcript.js'
import type { Check, EudikitErrorCode, VerificationResult } from '../types.js'
import { EudikitError } from '../types.js'
import { runVerification } from '../verify/engine.js'
import { openResponseEnvelope, peekJweKid } from '../verify/envelope.js'
import { RESULT_KEY_PREFIX, toResultRecord } from '../verify/result-record.js'
import type { ResolvedVerifierConfig } from './config.js'
import {
  JWE_KID_KEY_PREFIX,
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

  const jwe = form.get('response')
  if (jwe !== null && jwe !== '') {
    return handleEncryptedResponse(config, presets, jwe)
  }
  return handlePlainResponse(config, presets, form)
}

// ---------------------------------------------------------------------------
// direct_post (clear form fields)
// ---------------------------------------------------------------------------

async function handlePlainResponse(
  config: ResolvedVerifierConfig,
  presets: PresetRegistry,
  form: URLSearchParams
): Promise<Response> {
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

  const encryptionExpected = record.ephemeralPrivateJwk !== undefined

  const walletError = form.get('error')
  if (walletError !== null) {
    // A wallet MAY send its error response unencrypted even when the request asked for
    // direct_post.jwt — an error carries no credential to protect.
    const checks = [
      ...sessionChecks(record, { stateCheck: 'passed' }),
      ...(encryptionExpected
        ? [
            envelopeRow(
              'envelope.jwe_decrypted',
              'skipped',
              'the wallet sent its error response unencrypted, which the spec permits'
            ),
            envelopeRow('envelope.key_binding', 'skipped', 'no envelope on an error response'),
          ]
        : plainEnvelopeRows()),
    ]
    const result = failedResult(config, record, state, checks, {
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

  if (encryptionExpected) {
    // This request demanded direct_post.jwt; posting the credential in the clear breaks the
    // §14.5 envelope contract, and accepting it would silently downgrade every deployment.
    const checks = [
      ...sessionChecks(record, { stateCheck: 'passed' }),
      envelopeRow(
        'envelope.jwe_decrypted',
        'failed',
        'the request demanded an encrypted response (direct_post.jwt) but the wallet posted ' +
          'clear form fields'
      ),
      envelopeRow('envelope.key_binding', 'failed', 'no JWE envelope to bind'),
    ]
    const result = failedResult(config, record, state, checks, {
      code: 'ENVELOPE_DECRYPTION_FAILED',
      message: 'the wallet answered an encrypted-response request with an unencrypted response',
    })
    return respondStored(config, record, state, result)
  }

  const vpToken = parseVpTokenForm(form)
  const baseChecks = [...sessionChecks(record, { stateCheck: 'passed' }), ...plainEnvelopeRows()]

  let result: VerificationResult
  if (vpToken === null) {
    result = failedResult(config, record, state, baseChecks, {
      code: 'PRESENTATION_MALFORMED',
      message: 'the response carries neither a parseable vp_token nor an error field',
    })
  } else {
    result = await verifyResponse(config, presets, record, state, vpToken, baseChecks, null)
  }
  return respondStored(config, record, state, result)
}

// ---------------------------------------------------------------------------
// direct_post.jwt (single `response` JWE field)
// ---------------------------------------------------------------------------

async function handleEncryptedResponse(
  config: ResolvedVerifierConfig,
  presets: PresetRegistry,
  jwe: string
): Promise<Response> {
  const kid = peekJweKid(jwe)
  if (kid === null) return invalidRequest(400)

  // The kid → session index is consumed atomically together with the request record, so a
  // replayed JWE finds nothing on either key.
  const index = await config.session.consume(`${JWE_KID_KEY_PREFIX}${kid}`)
  if (index === null || index.v !== 1 || typeof index.sessionId !== 'string') {
    return invalidRequest(400)
  }
  const state = index.sessionId

  const stored = await config.session.consume(`${REQUEST_KEY_PREFIX}${state}`)
  if (stored === null) return invalidRequest(400)

  const record = parsePendingRequestRecord(stored)
  if (
    record === null ||
    record.state !== state ||
    record.responseUri === undefined ||
    record.ephemeralPrivateJwk === undefined
  ) {
    return invalidRequest(400)
  }

  const envelope = await openResponseEnvelope({
    jwe,
    privateJwk: record.ephemeralPrivateJwk,
    nonce: record.nonce,
  })

  if (!envelope.ok) {
    const checks = [...sessionChecks(record, { stateCheck: 'skipped' }), ...envelope.checks]
    const result = failedResult(config, record, state, checks, {
      code: envelope.error.code,
      message: envelope.error.message,
    })
    return respondStored(config, record, state, result)
  }

  const payload = envelope.payload
  const stateCheck: Check['status'] = payload.state === record.state ? 'passed' : 'failed'
  const baseChecks = [...sessionChecks(record, { stateCheck }), ...envelope.checks]

  const walletError = payload.error
  if (typeof walletError === 'string') {
    const description = payload.error_description
    const result = failedResult(config, record, state, baseChecks, {
      code: mapWalletError(walletError),
      message:
        typeof description === 'string'
          ? `the wallet returned "${walletError}": ${description}`
          : `the wallet returned "${walletError}"`,
      walletError,
    })
    await storeResult(config, state, result)
    return new Response(JSON.stringify({}), { status: 200, headers: JSON_HEADERS })
  }

  const vpToken = coerceVpTokenMap(payload.vp_token)
  let result: VerificationResult
  if (vpToken === null) {
    result = failedResult(config, record, state, baseChecks, {
      code: 'PRESENTATION_MALFORMED',
      message: 'the decrypted response carries neither a parseable vp_token nor an error field',
    })
  } else {
    result = await verifyResponse(
      config,
      presets,
      record,
      state,
      vpToken,
      baseChecks,
      thumbprintOf(record)
    )
  }
  return respondStored(config, record, state, result)
}

/** The handover thumbprint is the raw bytes of the ephemeral key's RFC 7638 kid. */
function thumbprintOf(record: PendingRequestRecord): Uint8Array | null {
  const kid = record.ephemeralPrivateJwk?.kid
  if (typeof kid !== 'string' || kid === '') return null
  return Uint8Array.from(Buffer.from(kid, 'base64url'))
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
  baseChecks: Check[],
  jwkThumbprint: Uint8Array | null
): Promise<VerificationResult> {
  // The wallet signed the SessionTranscript over the values of the authorization request;
  // rebuilding it from the session record is what binds this response to that exact request
  // (nonce binding lives here). Encrypted flows bind the ephemeral key too: the handover
  // carries its RFC 7638 thumbprint instead of null.
  const responseUri = record.responseUri as string
  const sessionTranscript = buildOpenID4VPSessionTranscript({
    clientId: record.clientId ?? `redirect_uri:${responseUri}`,
    nonce: record.nonce,
    jwkThumbprint,
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
 * Session-class checks for a consumed direct_post record. Most read as all-passed by
 * construction — a session that failed them never reaches result production — and are listed
 * anyway because every result carries the full report. The `state` check is the exception:
 * on encrypted flows the state travels inside the JWE and is judged after decryption.
 */
function sessionChecks(
  record: PendingRequestRecord,
  options: { stateCheck: Check['status'] }
): Check[] {
  return [
    { id: 'session.found', status: 'passed', detail: 'the response resolved to a pending request' },
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
    {
      id: 'session.state_match',
      status: options.stateCheck,
      detail:
        options.stateCheck === 'passed'
          ? 'the response state equals the stored state'
          : options.stateCheck === 'failed'
            ? 'the state inside the decrypted response does not equal the stored state'
            : 'the envelope did not open; no state to compare',
    },
    {
      id: 'session.response_mode_match',
      status: 'passed',
      detail: `the ${record.channel} channel expects a ${
        record.ephemeralPrivateJwk !== undefined ? 'direct_post.jwt' : 'direct_post'
      } response`,
    },
    {
      id: 'session.origin_allowed',
      status: 'skipped',
      detail:
        'browser-attested origins exist only on the Digital Credentials API channel; the ' +
        'direct_post binding is nonce + state + response_uri',
    },
  ]
}

function plainEnvelopeRows(): Check[] {
  return [
    envelopeRow(
      'envelope.jwe_decrypted',
      'skipped',
      'this request used unencrypted direct_post (no JWE envelope)'
    ),
    envelopeRow(
      'envelope.key_binding',
      'skipped',
      'no response encryption key on an unencrypted flow'
    ),
  ]
}

function envelopeRow(
  id: 'envelope.jwe_decrypted' | 'envelope.key_binding',
  status: Check['status'],
  detail: string
): Check {
  return { id, status, detail }
}

// ---------------------------------------------------------------------------
// vp_token parsing (standard JSON field + iOS bracket fields)
// ---------------------------------------------------------------------------

function parseVpTokenForm(form: URLSearchParams): Record<string, string[]> | null {
  const out: Record<string, string[]> = {}

  const raw = form.get('vp_token')
  if (raw !== null) {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      return null
    }
    const map = coerceVpTokenMap(parsed)
    if (map === null) return null
    Object.assign(out, map)
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

/** The parsed `vp_token` value: query id → presentation list. Shared with the JWE payload path. */
export function coerceVpTokenMap(value: unknown): Record<string, string[]> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const out: Record<string, string[]> = {}
  for (const [queryId, entry] of Object.entries(value)) {
    const presentations = asPresentationList(entry)
    if (presentations === null) return null
    out[queryId] = presentations
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
// failure results + storage
// ---------------------------------------------------------------------------

/**
 * OpenID4VP §8.5 error → our taxonomy. `access_denied` deliberately collapses "no matching
 * credential", "no consent" and "could not authenticate" (the spec merges them and wallets are
 * encouraged to stay silent); the `invalid_*` family means the wallet rejected *our* request.
 */
export function mapWalletError(code: string): EudikitErrorCode {
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

/**
 * Store first, respond second: a 200 to the wallet is the promise that the outcome is already
 * pollable. Redirect mode substitutes a fresh response code into the configured template.
 */
async function respondStored(
  config: ResolvedVerifierConfig,
  record: PendingRequestRecord,
  state: string,
  result: VerificationResult
): Promise<Response> {
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

export async function storeResult(
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
