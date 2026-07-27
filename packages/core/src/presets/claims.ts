/**
 * Shared claim-reading helpers for the preset `extract` functions.
 *
 * `VerifiedCredential.claims` keys follow the source format's own conventions: for mdoc it is
 * the data element identifier (the namespace is implied by `docType`), for SD-JWT VC it is the
 * top-level claim name with nested claims keeping their JSON structure
 * (e.g. `age_equal_or_over: { '18': true }`, `address: { country: 'DE' }`).
 */

import { EudikitError } from '../types.js'

export function malformed(detail: string): never {
  throw new EudikitError('PRESENTATION_MALFORMED', detail)
}

/** Walks a nested claim structure; returns `undefined` as soon as a step is missing. */
export function nestedClaim(claims: Record<string, unknown>, path: string[]): unknown {
  let current: unknown = claims
  for (const segment of path) {
    if (current === null || typeof current !== 'object') return undefined
    current = (current as Record<string, unknown>)[segment]
  }
  return current
}

/**
 * Normalizes a claim that is a string or an array of strings into a de-duplicated string array,
 * preserving first-seen order. Anything else is a malformed presentation.
 */
export function asStringSet(value: unknown, description: string): string[] {
  const values = Array.isArray(value) ? value : [value]
  for (const entry of values) {
    if (typeof entry !== 'string') {
      malformed(`${description} must be a string or an array of strings`)
    }
  }
  return [...new Set(values as string[])]
}
