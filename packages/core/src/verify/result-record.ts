/**
 * Serialization of a `VerificationResult` into the session store and back.
 *
 * The store holds JSON, so the two non-JSON shapes are converted at the boundary: `Date`s in
 * credential validity become ISO strings, and the `EudikitError` becomes a `{code, message,
 * walletError}` triple that is rehydrated into a real error instance on read. The record shape
 * is versioned and internal — not a public contract.
 */

import type {
  EudikitErrorCode,
  StoredRecord,
  VerificationResult,
  VerifiedCredential,
} from '../types.js'
import { EudikitError } from '../types.js'

export const RESULT_KEY_PREFIX = 'result:'

interface SerializedCredential extends Omit<VerifiedCredential, 'validity'> {
  validity: { validFrom: string; validUntil: string; signedAt?: string }
}

interface SerializedError {
  code: EudikitErrorCode
  message: string
  walletError?: string
}

export interface StoredResultRecord extends Record<string, unknown> {
  v: 1
  status: 'verified' | 'failed'
  responseCode?: string
  result: {
    verified: boolean
    profile: VerificationResult['profile']
    policy: VerificationResult['policy']
    claims: unknown
    credentials: SerializedCredential[]
    diagnostics: VerificationResult['diagnostics']
    error: SerializedError | null
    sessionId: string
  }
}

export function toResultRecord(
  result: VerificationResult,
  responseCode?: string
): StoredResultRecord {
  return {
    v: 1,
    status: result.verified ? 'verified' : 'failed',
    ...(responseCode !== undefined ? { responseCode } : {}),
    result: {
      verified: result.verified,
      profile: result.profile,
      policy: result.policy,
      claims: result.claims,
      sessionId: result.sessionId,
      credentials: result.credentials.map((credential) => ({
        ...credential,
        validity: {
          validFrom: credential.validity.validFrom.toISOString(),
          validUntil: credential.validity.validUntil.toISOString(),
          ...(credential.validity.signedAt !== undefined
            ? { signedAt: credential.validity.signedAt.toISOString() }
            : {}),
        },
      })),
      diagnostics: result.diagnostics,
      error:
        result.error === null
          ? null
          : {
              code: result.error.code,
              message: result.error.message,
              ...(result.error.walletError !== undefined
                ? { walletError: result.error.walletError }
                : {}),
            },
    },
  }
}

export function parseResultRecord(record: StoredRecord): StoredResultRecord | null {
  if (record.v !== 1) return null
  if (record.status !== 'verified' && record.status !== 'failed') return null
  if (typeof record.result !== 'object' || record.result === null) return null
  return record as StoredResultRecord
}

export function fromResultRecord(record: StoredResultRecord): VerificationResult {
  const stored = record.result
  return {
    verified: stored.verified,
    profile: stored.profile,
    policy: stored.policy,
    claims: stored.claims as Record<string, unknown> | null,
    credentials: stored.credentials.map((credential) => ({
      ...credential,
      validity: {
        validFrom: new Date(credential.validity.validFrom),
        validUntil: new Date(credential.validity.validUntil),
        ...(credential.validity.signedAt !== undefined
          ? { signedAt: new Date(credential.validity.signedAt) }
          : {}),
      },
    })),
    diagnostics: stored.diagnostics,
    error:
      stored.error === null
        ? null
        : new EudikitError(stored.error.code, stored.error.message, {
            ...(stored.error.walletError !== undefined
              ? { walletError: stored.error.walletError }
              : {}),
          }),
    sessionId: stored.sessionId,
  }
}
