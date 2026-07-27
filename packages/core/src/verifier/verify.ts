/**
 * `verifier.verify()` — the server-side entry point for Digital Credentials API responses.
 *
 * The caller carries the session id in its own context (the DC API has no `state`), posts the
 * browser's `DigitalCredential` back as `{ protocol, data }`, and this function consumes the
 * session atomically: the second call for the same id throws `SESSION_ALREADY_CONSUMED`, which
 * is the DC API channel's replay defense. Wallet- and verification-class outcomes never throw
 * — they come back as `{ verified: false, error, diagnostics }`; throwing is reserved for
 * programming and configuration errors (unknown session, wrong channel, unsupported protocol,
 * missing `expectedOrigins`).
 *
 * Origin binding: the wallet signs over a SessionTranscript whose handover contains the origin
 * of the page that invoked the DC API — a value the response itself does not carry. The
 * verifier therefore rebuilds the transcript from its own `expectedOrigins` allowlist,
 * accepting the first origin whose transcript the device signature verifies against. That the
 * signature verifies IS the proof of origin (`session.origin_allowed`); when no configured
 * origin fits, the response was produced for a page this verifier does not vouch for — or the
 * signature is simply invalid — and the result says exactly that.
 */

import { buildOpenID4VPDCAPISessionTranscript } from '../mdoc/session-transcript.js'
import type { Check, VerificationResult, VerifyInput } from '../types.js'
import { EudikitError } from '../types.js'
import { runVerification } from '../verify/engine.js'
import { openResponseEnvelope } from '../verify/envelope.js'
import { RESULT_KEY_PREFIX } from '../verify/result-record.js'
import type { ResolvedVerifierConfig } from './config.js'
import {
  type PendingRequestRecord,
  parsePendingRequestRecord,
  REQUEST_KEY_PREFIX,
} from './create-request.js'
import { coerceVpTokenMap, mapWalletError, storeResult } from './handle-wallet-response.js'
import type { PresetRegistry } from './preset-registry.js'

const SUPPORTED_PROTOCOLS = new Set(['openid4vp-v1-unsigned', 'openid4vp-v1-signed'])

export async function verifyDcApiResponse(
  config: ResolvedVerifierConfig,
  presets: PresetRegistry,
  input: VerifyInput
): Promise<VerificationResult> {
  if (typeof input !== 'object' || input === null) {
    throw new EudikitError('CONFIG_INVALID', 'verify(input) needs an input object')
  }
  const { sessionId, response } = input
  if (typeof sessionId !== 'string' || sessionId === '') {
    throw new EudikitError('CONFIG_INVALID', 'verify() needs a non-empty sessionId string')
  }
  if (typeof response !== 'object' || response === null || typeof response.protocol !== 'string') {
    throw new EudikitError(
      'CONFIG_INVALID',
      'verify() needs the serialized DigitalCredential: { protocol, data }'
    )
  }
  if (!SUPPORTED_PROTOCOLS.has(response.protocol)) {
    throw new EudikitError(
      'UNSUPPORTED_PROTOCOL',
      `response protocol "${response.protocol}" is not in this release's set ` +
        '(openid4vp-v1-unsigned, openid4vp-v1-signed) — org-iso-mdoc (ISO 18013-7 Annex C) ' +
        'is planned as a protocol adapter in a later release'
    )
  }

  const stored = await config.session.consume(`${REQUEST_KEY_PREFIX}${sessionId}`)
  if (stored === null) {
    const finished = await config.session.get(`${RESULT_KEY_PREFIX}${sessionId}`)
    throw finished !== null
      ? new EudikitError(
          'SESSION_ALREADY_CONSUMED',
          'this session was already verified once — read the stored outcome with getResult()'
        )
      : new EudikitError(
          'SESSION_NOT_FOUND',
          'no pending request for this sessionId (never created, expired, or already consumed ' +
            'and past its result TTL)'
        )
  }

  const record = parsePendingRequestRecord(stored)
  if (record === null || record.channel !== 'dc-api') {
    throw new EudikitError(
      'CONFIG_INVALID',
      'this session does not belong to the dc-api channel: QR/deep-link sessions complete ' +
        'through handleWalletResponse (direct_post), not verify()'
    )
  }
  if (record.expectedOrigins.length === 0) {
    throw new EudikitError(
      'CONFIG_INVALID',
      'verifying a DC API response requires expectedOrigins: the wallet signs over the ' +
        'invoking page origin, and without an allowlist the SessionTranscript cannot be ' +
        'rebuilt — set expectedOrigins in the verifier config or per request'
    )
  }

  const encrypted = record.ephemeralPrivateJwk !== undefined
  const data = asRecord(response.data)

  // Shape guard doubles as the response_mode check: an encrypted request expects
  // { response: <JWE> }, an unencrypted one expects the parameters in the clear.
  const jwe = data !== null && typeof data.response === 'string' ? data.response : null
  if (encrypted !== (jwe !== null)) {
    const checks = [...dcApiSessionChecks(record, false), envelopeMismatchRow(encrypted)]
    return finish(
      config,
      sessionId,
      failed(config, record, sessionId, checks, {
        code: 'ENVELOPE_DECRYPTION_FAILED',
        message: encrypted
          ? 'the request demanded dc_api.jwt but the response carries no JWE envelope'
          : 'an encrypted response arrived for a request that provisioned no encryption key',
      })
    )
  }

  let payload: Record<string, unknown> | null
  let envelopeChecks: Check[]
  if (encrypted && jwe !== null && record.ephemeralPrivateJwk !== undefined) {
    const envelope = await openResponseEnvelope({
      jwe,
      privateJwk: record.ephemeralPrivateJwk,
      nonce: record.nonce,
    })
    if (!envelope.ok) {
      const checks = [...dcApiSessionChecks(record, true), ...envelope.checks]
      return finish(
        config,
        sessionId,
        failed(config, record, sessionId, checks, {
          code: envelope.error.code,
          message: envelope.error.message,
        })
      )
    }
    payload = envelope.payload
    envelopeChecks = envelope.checks
  } else {
    payload = data
    envelopeChecks = [
      {
        id: 'envelope.jwe_decrypted',
        status: 'skipped',
        detail: 'response mode dc_api is unencrypted (no JWE envelope)',
      },
      {
        id: 'envelope.key_binding',
        status: 'skipped',
        detail: 'no response encryption key on an unencrypted flow',
      },
    ]
  }

  const baseChecks = [...dcApiSessionChecks(record, true), ...envelopeChecks]

  if (payload === null) {
    return finish(
      config,
      sessionId,
      failed(config, record, sessionId, baseChecks, {
        code: 'PRESENTATION_MALFORMED',
        message: 'the DC API response data is not an object of response parameters',
      })
    )
  }

  const walletError = payload.error
  if (typeof walletError === 'string') {
    const description = payload.error_description
    return finish(
      config,
      sessionId,
      failed(config, record, sessionId, baseChecks, {
        code: mapWalletError(walletError),
        message:
          typeof description === 'string'
            ? `the wallet returned "${walletError}": ${description}`
            : `the wallet returned "${walletError}"`,
        walletError,
      })
    )
  }

  const vpToken = coerceVpTokenMap(payload.vp_token)
  if (vpToken === null) {
    return finish(
      config,
      sessionId,
      failed(config, record, sessionId, baseChecks, {
        code: 'PRESENTATION_MALFORMED',
        message: 'the response carries neither a parseable vp_token nor an error field',
      })
    )
  }

  const jwkThumbprint = encrypted ? thumbprintOf(record) : null
  const result = await verifyAgainstOrigins(
    config,
    presets,
    record,
    sessionId,
    vpToken,
    baseChecks,
    jwkThumbprint
  )
  return finish(config, sessionId, result)
}

/**
 * Runs the chain once per candidate origin and keeps the run whose transcript the device
 * signature verified against. A response signed for none of them is reported through the
 * first candidate's run plus a failed `session.origin_allowed` — with the honest caveat that
 * "wrong origin" and "broken signature" are indistinguishable from the outside.
 */
async function verifyAgainstOrigins(
  config: ResolvedVerifierConfig,
  presets: PresetRegistry,
  record: PendingRequestRecord,
  sessionId: string,
  vpToken: Record<string, string[]>,
  baseChecks: Check[],
  jwkThumbprint: Uint8Array | null
): Promise<VerificationResult> {
  const preset = record.presetId !== undefined ? presets.get(record.presetId) : undefined

  const run = (origin: string, originCheck: Check): Promise<VerificationResult> =>
    runVerification({
      vpToken,
      dcql: record.dcql,
      sessionTranscript: buildOpenID4VPDCAPISessionTranscript({
        origin,
        nonce: record.nonce,
        jwkThumbprint,
      }),
      trust: config.trust,
      profile: record.profile,
      sessionId,
      now: config.now(),
      baseChecks: [...baseChecks, originCheck],
      ...(preset !== undefined ? { preset } : {}),
    })

  for (const origin of record.expectedOrigins) {
    const result = await run(origin, {
      id: 'session.origin_allowed',
      status: 'passed',
      detail: 'device authentication verified against the transcript of an allowed origin',
    })
    if (deviceSignatureBound(result)) return result
  }

  const firstOrigin = record.expectedOrigins[0] as string
  return run(firstOrigin, {
    id: 'session.origin_allowed',
    status: 'failed',
    detail:
      `the device signature verified against none of the ${record.expectedOrigins.length} ` +
      'expected origin(s) — the response was produced for an origin outside the allowlist, ' +
      'or the signature is invalid (the two are cryptographically indistinguishable here)',
  })
}

/** At least one device signature verified and none failed — the transcript (origin) fits. */
function deviceSignatureBound(result: VerificationResult): boolean {
  const rows = result.diagnostics.filter((check) => check.id === 'mdoc.device_signature_valid')
  return rows.length > 0 && rows.every((check) => check.status === 'passed')
}

function dcApiSessionChecks(record: PendingRequestRecord, modeMatched: boolean): Check[] {
  return [
    { id: 'session.found', status: 'passed', detail: 'sessionId resolved to a pending request' },
    {
      id: 'session.single_use',
      status: 'passed',
      detail: 'the pending request was consumed atomically; a second verify() call throws',
    },
    {
      id: 'session.not_expired',
      status: 'passed',
      detail: 'the record was still live in the session store (TTL not reached)',
    },
    {
      id: 'session.state_match',
      status: 'skipped',
      detail: 'the DC API defines no state parameter; the session id travels in the caller context',
    },
    {
      id: 'session.response_mode_match',
      status: modeMatched ? 'passed' : 'failed',
      detail: modeMatched
        ? `the response shape matches ${record.ephemeralPrivateJwk !== undefined ? 'dc_api.jwt' : 'dc_api'}`
        : 'the response shape does not match the requested response mode',
    },
  ]
}

function envelopeMismatchRow(encrypted: boolean): Check {
  return {
    id: 'envelope.jwe_decrypted',
    status: 'failed',
    detail: encrypted
      ? 'expected { response: <JWE> } (dc_api.jwt) but the data carries clear parameters'
      : 'received { response: <JWE> } on a request that provisioned no encryption key',
  }
}

function thumbprintOf(record: PendingRequestRecord): Uint8Array | null {
  const kid = record.ephemeralPrivateJwk?.kid
  if (typeof kid !== 'string' || kid === '') return null
  return Uint8Array.from(Buffer.from(kid, 'base64url'))
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  return value as Record<string, unknown>
}

function failed(
  config: ResolvedVerifierConfig,
  record: PendingRequestRecord,
  sessionId: string,
  checks: Check[],
  failure: { code: EudikitError['code']; message: string; walletError?: string }
): VerificationResult {
  return {
    verified: false,
    profile: record.profile,
    policy: config.trust.mode,
    claims: null,
    credentials: [],
    diagnostics: checks,
    error: new EudikitError(failure.code, failure.message, {
      ...(failure.walletError !== undefined ? { walletError: failure.walletError } : {}),
    }),
    sessionId,
  }
}

/** Every outcome is stored before it is returned, so getResult() and replay detection work. */
async function finish(
  config: ResolvedVerifierConfig,
  sessionId: string,
  result: VerificationResult
): Promise<VerificationResult> {
  await storeResult(config, sessionId, result)
  return result
}
