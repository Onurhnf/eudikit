/**
 * Shared claim-reading helpers for the preset `extract` functions, plus the value-description
 * rules the DCQL post-validation reuses for its claim-type diagnostics.
 *
 * `VerifiedCredential.claims` keys follow the source format's own conventions: for mdoc it is
 * the data element identifier (the namespace is implied by `docType`), for SD-JWT VC it is the
 * top-level claim name with nested claims keeping their JSON structure
 * (e.g. `age_equal_or_over: { '18': true }`, `address: { country: 'DE' }`).
 */

import { type ClaimValueType, EudikitError } from '../types.js'

export function malformed(detail: string): never {
  throw new EudikitError('PRESENTATION_MALFORMED', detail)
}

/** Longest string value that may appear verbatim in a diagnostic message. */
const MAX_SHOWN_STRING_LENGTH = 32

const CONTROL_CHARACTERS = /\p{Cc}/u

/**
 * Describes a claim value for a diagnostic message: the type name, plus the value itself when
 * showing it cannot leak more than a few characters of data — booleans, numbers, and short
 * control-character-free strings. Everything else (objects, arrays, long strings) is named by
 * type only, and `redactValue` forces the type-only form even for the safe primitives, for
 * claims whose value is personal data no matter how short it is.
 */
export function describeValue(value: unknown, options?: { redactValue?: boolean }): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'
  if (Array.isArray(value)) return 'an array'
  const redact = options?.redactValue === true
  switch (typeof value) {
    case 'boolean':
    case 'number':
      return redact ? `a ${typeof value}` : `a ${typeof value} (${String(value)})`
    case 'string':
      return !redact && value.length <= MAX_SHOWN_STRING_LENGTH && !CONTROL_CHARACTERS.test(value)
        ? `a string ("${value}")`
        : 'a string'
    case 'object':
      return 'an object'
    default:
      return `a ${typeof value}`
  }
}

/**
 * The diagnostic sentence for a claim that arrived with a value of the wrong type — precise
 * enough to diagnose a mis-issued credential without decoding bytes by hand. `undefined` means
 * nothing arrived at all, so the issuance clause is dropped for it.
 */
export function wrongClaimType(
  expected: ClaimValueType,
  claimName: string,
  value: unknown,
  options?: { redactValue?: boolean }
): string {
  const cause =
    value === undefined ? '' : ' — the credential was issued with a value of the wrong type'
  return `expected a ${expected} "${claimName}" claim, received ${describeValue(value, options)}${cause}`
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
  const isArray = Array.isArray(value)
  const values = isArray ? value : [value]
  for (const entry of values) {
    if (typeof entry !== 'string') {
      const received = isArray
        ? `an array containing ${describeValue(entry)}`
        : describeValue(value)
      malformed(`${description} must be a string or an array of strings, received ${received}`)
    }
  }
  return [...new Set(values as string[])]
}
