/**
 * CBOR-decoded claim values → JSON-safe values.
 *
 * `VerifiedCredential.claims` travels through the session store (JSON) and out of the public
 * API, so every CBOR-native shape has to land on a JSON type first: Maps become objects, byte
 * strings become base64url, and CBOR full-dates (tag 1004 / tag 0, surfaced by the decoder as
 * date-like objects) become their ISO string.
 */

const BASE64URL_BYTES_PREFIX = 'base64url:'

export function jsonSafeClaims(claims: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(claims)) {
    out[key] = jsonSafeValue(value)
  }
  return out
}

export function jsonSafeValue(value: unknown): unknown {
  if (value === null || value === undefined) return value ?? null
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return value
    case 'number':
      return Number.isFinite(value) ? value : String(value)
    case 'bigint':
      return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(value)
        : value.toString()
    case 'object':
      break
    default:
      return String(value)
  }

  if (value instanceof Uint8Array) {
    return `${BASE64URL_BYTES_PREFIX}${Buffer.from(value).toString('base64url')}`
  }
  if (value instanceof Date) {
    return value.toISOString()
  }
  if (Array.isArray(value)) {
    return value.map(jsonSafeValue)
  }
  if (value instanceof Map) {
    const out: Record<string, unknown> = {}
    for (const [key, entry] of value) {
      out[String(key)] = jsonSafeValue(entry)
    }
    return out
  }
  // DateOnly (`full-date`) and similar wrapper objects stringify to their calendar value.
  const stringified = maybeCalendarString(value)
  if (stringified !== null) return stringified

  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) {
    out[key] = jsonSafeValue(entry)
  }
  return out
}

/**
 * The CBOR decoder surfaces `full-date` values as objects whose `toISOString`/`toString`
 * renders the date. Detect them without importing the concrete class.
 */
function maybeCalendarString(value: object): string | null {
  const candidate = value as { toISOString?: () => string }
  if (typeof candidate.toISOString === 'function') {
    const iso = candidate.toISOString()
    return typeof iso === 'string' ? iso : null
  }
  return null
}
