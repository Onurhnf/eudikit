/**
 * Shared helpers for the preset and DCQL builder tests.
 *
 * Every query eudikit emits has to be accepted by the wider ecosystem, not only by our own
 * structural checks — so `crossValidate` runs a query through the `dcql` package's parser and
 * semantic validator, the same implementation wallet-side stacks build on.
 */

import { DcqlQuery } from 'dcql'
import type { CredentialFormat, EudikitErrorCode, VerifiedCredential } from '../src/types.js'
import { EudikitError } from '../src/types.js'

export function crossValidate(query: unknown): void {
  const parsed = DcqlQuery.parse(query as Parameters<typeof DcqlQuery.parse>[0])
  DcqlQuery.validate(parsed)
}

/**
 * Runs `fn` (sync or async) expecting it to throw an `EudikitError` with `code`; returns the
 * error so tests can also assert on the message.
 */
export async function expectEudikitError(
  fn: () => unknown,
  code: EudikitErrorCode
): Promise<EudikitError> {
  try {
    await fn()
  } catch (error) {
    if (!(error instanceof EudikitError)) throw error
    if (error.code !== code) {
      throw new Error(`expected EudikitError ${code}, got ${error.code}: ${error.message}`)
    }
    return error
  }
  throw new Error(`expected EudikitError ${code}, but nothing was thrown`)
}

/** Minimal verified-credential fixture; only the fields `extract` reads carry real data. */
export function verifiedCredential(
  queryId: string,
  format: CredentialFormat,
  claims: Record<string, unknown>
): VerifiedCredential {
  return {
    queryId,
    format,
    claims,
    issuer: { subject: 'CN=Test Issuer', trustedListEntry: null },
    validity: { validFrom: new Date(0), validUntil: new Date(4102444800000) },
  }
}
