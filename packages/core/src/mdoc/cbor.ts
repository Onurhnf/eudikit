/**
 * A minimal, deterministic CBOR **encoder** — just enough for the fixed shapes that
 * `SessionTranscript` and the OpenID4VP handovers are made of (RFC 8949).
 *
 * Why we write our own rather than pull in a CBOR library:
 *
 *  - These structures get **hashed**, so the encoding must be deterministic. Everything here is
 *    deterministic by construction: shortest-form head, definite lengths, no indefinite chunks,
 *    no tags, no floats, no maps (so no key-ordering question can arise).
 *  - The obvious dependency, `cbor-x`, ships an `eval`-based decoder that breaks under strict CSP
 *    and on some edge runtimes. This file is ~90 lines and has no dependency at all, so that
 *    risk simply does not enter the tree.
 *
 * Supported major types: unsigned int heads (lengths only), byte strings (2), text strings (3),
 * arrays (4) and `null` (simple 22). Anything else is out of scope on purpose — if a future
 * structure needs maps or tags, add them here with test vectors, not ad hoc.
 */

const MT_BYTE_STRING = 0x40
const MT_TEXT_STRING = 0x60
const MT_ARRAY = 0x80

/** CBOR simple value 22 — `null` (`f6`). */
export const CBOR_NULL: Uint8Array = Uint8Array.of(0xf6)

const MAX_LENGTH = 0xffffffff

/**
 * Encodes a CBOR head: the major type plus its argument, always in the **shortest** form the
 * value fits into. Shortest-form is what makes the encoding deterministic, and therefore what
 * makes the hash reproducible.
 */
function encodeHead(majorType: number, argument: number): Uint8Array {
  if (!Number.isInteger(argument) || argument < 0) {
    throw new TypeError(`CBOR head argument must be a non-negative integer, got ${argument}`)
  }
  if (argument < 24) return Uint8Array.of(majorType | argument)
  if (argument <= 0xff) return Uint8Array.of(majorType | 24, argument)
  if (argument <= 0xffff) return Uint8Array.of(majorType | 25, argument >>> 8, argument & 0xff)
  if (argument <= MAX_LENGTH) {
    return Uint8Array.of(
      majorType | 26,
      (argument >>> 24) & 0xff,
      (argument >>> 16) & 0xff,
      (argument >>> 8) & 0xff,
      argument & 0xff
    )
  }
  // 64-bit heads are legal CBOR but no structure we encode can reach them.
  throw new RangeError(`CBOR head argument exceeds the supported range: ${argument}`)
}

export function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0
  for (const chunk of chunks) total += chunk.length
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

const utf8 = new TextEncoder()

/** Text string (major type 3). The length is the UTF-8 **byte** length, not the character count. */
export function encodeTextString(value: string): Uint8Array {
  const bytes = utf8.encode(value)
  return concatBytes([encodeHead(MT_TEXT_STRING, bytes.length), bytes])
}

/** Byte string (major type 2). */
export function encodeByteString(value: Uint8Array): Uint8Array {
  return concatBytes([encodeHead(MT_BYTE_STRING, value.length), value])
}

/**
 * Definite-length array (major type 4) built from already-encoded items. Taking encoded items
 * rather than JavaScript values keeps this encoder free of any value→CBOR type guessing, which
 * is where deterministic encoders usually go wrong.
 */
export function encodeArray(items: readonly Uint8Array[]): Uint8Array {
  return concatBytes([encodeHead(MT_ARRAY, items.length), ...items])
}

/** Hex helper for tests, fixtures and diagnostics. */
export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out
}

/** Inverse of {@link toHex}; rejects malformed input rather than silently truncating. */
export function fromHex(hex: string): Uint8Array {
  const normalized = hex.replace(/\s+/g, '')
  if (normalized.length % 2 !== 0 || /[^0-9a-fA-F]/.test(normalized)) {
    throw new TypeError('Invalid hex string')
  }
  const out = new Uint8Array(normalized.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}
