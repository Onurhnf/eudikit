/**
 * `verifier.getResult()` — the frontend polling read.
 *
 * Non-destructive by design: polling happens on an interval and must be repeatable, so this
 * reads with `get`, never `consume`. The status is derived from which record still exists:
 * a result record wins, a still-pending request record means `pending`, and neither means the
 * TTLs have done their work — `expired`.
 *
 * In redirect mode the stored result carries the `response_code` that was substituted into the
 * wallet's `redirect_uri`. Reading such a result requires presenting that code (OpenID4VP 1.0
 * §14.3.3 — the response endpoint's internal interface is protected by fresh cryptographic
 * values); a missing or wrong code throws `RESPONSE_CODE_MISMATCH` rather than leaking the
 * outcome.
 */

import type { SessionStatus } from '../types.js'
import { EudikitError } from '../types.js'
import { fromResultRecord, parseResultRecord, RESULT_KEY_PREFIX } from '../verify/result-record.js'
import type { ResolvedVerifierConfig } from './config.js'
import { REQUEST_KEY_PREFIX } from './create-request.js'

export async function getResult(
  config: ResolvedVerifierConfig,
  sessionId: string,
  options?: { responseCode?: string }
): Promise<SessionStatus> {
  if (typeof sessionId !== 'string' || sessionId === '') {
    throw new EudikitError('CONFIG_INVALID', 'getResult needs a non-empty sessionId string')
  }

  const stored = await config.session.get(`${RESULT_KEY_PREFIX}${sessionId}`)
  if (stored !== null) {
    const record = parseResultRecord(stored)
    if (record === null) {
      throw new EudikitError('INTERNAL', 'stored result record has an unknown shape')
    }
    if (record.responseCode !== undefined && record.responseCode !== options?.responseCode) {
      throw new EudikitError(
        'RESPONSE_CODE_MISMATCH',
        'this result was produced in redirect mode and can only be read with the ' +
          'response_code the wallet redirect carried'
      )
    }
    const result = fromResultRecord(record)
    return record.status === 'verified'
      ? { status: 'verified', result }
      : { status: 'failed', result }
  }

  const pending = await config.session.get(`${REQUEST_KEY_PREFIX}${sessionId}`)
  if (pending !== null) return { status: 'pending' }

  return { status: 'expired' }
}
