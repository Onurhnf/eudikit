/**
 * The project's first tests, and deliberately so: if our deterministic CBOR encoding is wrong,
 * every verification claim eudikit makes is worthless, because `DeviceSigned.deviceAuth` is a
 * signature over these exact bytes.
 *
 * Source of the vectors: **OpenID Connect for Verifiable Presentations 1.0 — Final (9 July 2025),
 * Appendix B.2.6**, fetched from https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 * on 2026-07-27. Hex strings below are copied from the specification's own non-normative
 * examples; the CBOR-diagnostic comments are the spec's, kept so a reader can check by eye.
 *
 * Two groups of tests:
 *   (a) our encoder vs the specification's hex, byte for byte;
 *   (b) our encoder vs `@owf/mdoc`'s own builder, byte for byte — so a divergence in either
 *       implementation surfaces here instead of as a device signature that never validates.
 */

import { createHash, randomBytes } from 'node:crypto'
import { type MdocContext, SessionTranscript } from '@owf/mdoc'
import { describe, expect, it } from 'vitest'
import { encodeByteString, encodeTextString, fromHex, toHex } from '../src/mdoc/cbor.js'
import {
  buildOpenID4VPDCAPIHandover,
  buildOpenID4VPDCAPIHandoverInfo,
  buildOpenID4VPDCAPISessionTranscript,
  buildOpenID4VPHandover,
  buildOpenID4VPHandoverInfo,
  buildOpenID4VPSessionTranscript,
} from '../src/mdoc/session-transcript.js'

// ---------------------------------------------------------------------------
// Spec vectors — OpenID4VP 1.0 Final, Appendix B.2.6
// ---------------------------------------------------------------------------

/**
 * The SHA-256 thumbprint (RFC 7638) of the spec's example encryption key:
 * `{"kty":"EC","crv":"P-256","x":"DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",`
 * `"y":"XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc","use":"enc","alg":"ECDH-ES","kid":"1"}`
 */
const JWK_THUMBPRINT = fromHex('4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047')

const NONCE = 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA'
const CLIENT_ID = 'x509_san_dns:example.com'
const RESPONSE_URI = 'https://example.com/response'
const ORIGIN = 'https://example.com'

/** B.2.6.1 — invocation via redirects (QR / deep link). */
const REDIRECT = {
  // 84                       # array(4)
  //   78 18 "x509_san_dns:example.com"
  //   78 2b "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
  //   58 20 <32-byte thumbprint>
  //   78 1c "https://example.com/response"
  handoverInfo:
    '847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767' +
    '426b786a7831726463397564527276654b7653734a4971383061766c58654c486847' +
    '7771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6' +
    'bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365',
  // 82                       # array(2)
  //   71    "OpenID4VPHandover"
  //   58 20 <sha-256 of the bytes above>
  handover:
    '82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494c' +
    'efdd9d95240d254b046b11b68013722aad38ac',
  // 83 f6 f6 <handover>      # [ null, null, Handover ]
  sessionTranscript:
    '83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e' +
    'ed494cefdd9d95240d254b046b11b68013722aad38ac',
} as const

/** B.2.6.2 — invocation via the Digital Credentials API. */
const DCAPI = {
  // 83                       # array(3)
  //   73    "https://example.com"     <- bare origin, no "origin:" prefix
  //   78 2b <nonce>
  //   58 20 <32-byte thumbprint>
  handoverInfo:
    '837368747470733a2f2f6578616d706c652e636f6d782b6578633767426b786a7831' +
    '726463397564527276654b7653734a4971383061766c58654c486847777174415820' +
    '4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047',
  handover:
    '82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f97' +
    '62c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a',
  sessionTranscript:
    '83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4' +
    '212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a',
} as const

// ---------------------------------------------------------------------------
// (a) Our encoder against the specification's hex
// ---------------------------------------------------------------------------

describe('OpenID4VP 1.0 B.2.6.1 — invocation via redirects (QR / deep link)', () => {
  const input = {
    clientId: CLIENT_ID,
    nonce: NONCE,
    jwkThumbprint: JWK_THUMBPRINT,
    responseUri: RESPONSE_URI,
  }

  it('encodes OpenID4VPHandoverInfo exactly as the spec vector', () => {
    expect(toHex(buildOpenID4VPHandoverInfo(input))).toBe(REDIRECT.handoverInfo)
  })

  it('encodes OpenID4VPHandover exactly as the spec vector', () => {
    expect(toHex(buildOpenID4VPHandover(input))).toBe(REDIRECT.handover)
  })

  it('encodes SessionTranscript exactly as the spec vector', () => {
    expect(toHex(buildOpenID4VPSessionTranscript(input))).toBe(REDIRECT.sessionTranscript)
  })
})

describe('OpenID4VP 1.0 B.2.6.2 — invocation via the Digital Credentials API', () => {
  const input = { origin: ORIGIN, nonce: NONCE, jwkThumbprint: JWK_THUMBPRINT }

  it('encodes OpenID4VPDCAPIHandoverInfo exactly as the spec vector', () => {
    expect(toHex(buildOpenID4VPDCAPIHandoverInfo(input))).toBe(DCAPI.handoverInfo)
  })

  it('encodes OpenID4VPDCAPIHandover exactly as the spec vector', () => {
    expect(toHex(buildOpenID4VPDCAPIHandover(input))).toBe(DCAPI.handover)
  })

  it('encodes SessionTranscript exactly as the spec vector', () => {
    expect(toHex(buildOpenID4VPDCAPISessionTranscript(input))).toBe(DCAPI.sessionTranscript)
  })
})

// ---------------------------------------------------------------------------
// Encoding invariants the vectors let us pin down
// ---------------------------------------------------------------------------

describe('encoding invariants', () => {
  it('hashes the raw HandoverInfo CBOR, not a bstr-wrapped copy of it', () => {
    // The CDDL (`OpenID4VPHandoverInfoBytes = bstr .cbor OpenID4VPHandoverInfo`) reads as though
    // the byte-string header were part of what gets hashed. It is not, and the difference is
    // invisible until a real device signature fails to verify.
    const info = fromHex(REDIRECT.handoverInfo)
    const rawHash = createHash('sha256').update(info).digest('hex')
    const wrappedHash = createHash('sha256').update(encodeByteString(info)).digest('hex')

    expect(REDIRECT.handover).toContain(rawHash)
    expect(REDIRECT.handover).not.toContain(wrappedHash)
  })

  it('encodes an absent thumbprint as CBOR null (f6) — the unencrypted AV path', () => {
    // profile 'av' means plain direct_post: no response encryption, so no thumbprint. This is the
    // shape that matters most today, and the spec gives no hex vector for it.
    const info = buildOpenID4VPDCAPIHandoverInfo({
      origin: ORIGIN,
      nonce: NONCE,
      jwkThumbprint: null,
    })
    expect(toHex(info).endsWith('f6')).toBe(true)
    expect(toHex(info).startsWith('83')).toBe(true) // still a 3-element array
  })

  it('always uses the shortest-form length head', () => {
    // Deterministic encoding is not a style preference here: the bytes get hashed.
    expect(toHex(encodeTextString('a'.repeat(23))).slice(0, 2)).toBe('77') // head packed inline
    expect(toHex(encodeTextString('a'.repeat(24))).slice(0, 4)).toBe('7818') // 1-byte length
    expect(toHex(encodeTextString('a'.repeat(256))).slice(0, 6)).toBe('790100') // 2-byte length
  })

  it('measures text string length in UTF-8 bytes, not characters', () => {
    // 'ü' is two bytes; a naive .length would emit 0x61 and corrupt every downstream hash.
    expect(toHex(encodeTextString('ü'))).toBe('62c3bc')
  })
})

// ---------------------------------------------------------------------------
// (b) Byte comparison against @owf/mdoc's own builder
// ---------------------------------------------------------------------------

/**
 * `SessionTranscript.for*` needs only the digest callback, but the parameter type is the whole
 * crypto slice of `MdocContext`, so the unused members are present and loud.
 */
const mdocCryptoContext: Pick<MdocContext, 'crypto'> = {
  crypto: {
    random: (length: number) => new Uint8Array(randomBytes(length)),
    digest: ({ digestAlgorithm, bytes }) =>
      new Uint8Array(
        createHash(digestAlgorithm.replace('-', '').toLowerCase()).update(bytes).digest()
      ),
    hdkf: () => {
      throw new Error('hdkf is not used when building a SessionTranscript')
    },
  },
}

describe('byte compatibility with @owf/mdoc 0.7.0', () => {
  // What this proves: the library and our encoder agree, and both agree with the spec. What it
  // does NOT prove: that today's AV wallet produces spec-conformant bytes on a real device —
  // only an end-to-end device test can answer that.

  it('matches SessionTranscript.forOid4Vp (redirect / QR)', async () => {
    const theirs = await SessionTranscript.forOid4Vp(
      {
        clientId: CLIENT_ID,
        nonce: NONCE,
        jwkThumbprint: JWK_THUMBPRINT,
        responseUri: RESPONSE_URI,
      },
      mdocCryptoContext
    )
    const ours = buildOpenID4VPSessionTranscript({
      clientId: CLIENT_ID,
      nonce: NONCE,
      jwkThumbprint: JWK_THUMBPRINT,
      responseUri: RESPONSE_URI,
    })

    expect(toHex(theirs.encode())).toBe(toHex(ours))
    expect(toHex(theirs.encode())).toBe(REDIRECT.sessionTranscript)
  })

  it('matches SessionTranscript.forOid4VpDcApi (Digital Credentials API)', async () => {
    const theirs = await SessionTranscript.forOid4VpDcApi(
      { origin: ORIGIN, nonce: NONCE, jwkThumbprint: JWK_THUMBPRINT },
      mdocCryptoContext
    )
    const ours = buildOpenID4VPDCAPISessionTranscript({
      origin: ORIGIN,
      nonce: NONCE,
      jwkThumbprint: JWK_THUMBPRINT,
    })

    expect(toHex(theirs.encode())).toBe(toHex(ours))
    expect(toHex(theirs.encode())).toBe(DCAPI.sessionTranscript)
  })

  it('matches for the unencrypted case, where the thumbprint is absent', async () => {
    // The library models "no thumbprint" as an omitted optional; we model it as an explicit null.
    // This asserts the two agree on the wire — the case the AV profile actually uses.
    const theirs = await SessionTranscript.forOid4VpDcApi(
      { origin: ORIGIN, nonce: NONCE },
      mdocCryptoContext
    )
    const ours = buildOpenID4VPDCAPISessionTranscript({
      origin: ORIGIN,
      nonce: NONCE,
      jwkThumbprint: null,
    })

    expect(toHex(theirs.encode())).toBe(toHex(ours))
  })
})
